/*
   lru_cache.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2003-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2003-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */
#ifdef _WIN32
#include "linux-compat/bitops.h"
#include "linux-compat/seq_file.h" /* for seq_printf */
#include "linux/lru_cache.h"
#else
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/string.h> /* for memset */
#include <linux/seq_file.h> /* for seq_printf */
#include <linux/lru_cache.h>
#endif
#include "./drbd-kernel-compat/drbd_wrappers.h"

// MODIFIED_BY_MANTECH DW-1513 : Output LRU status like lc_seq_printf_stats function
#ifdef WIN_AL_BUG_ON
void private_strcat(char* buf, size_t buf_len, char* string, ULONG_PTR string_value){
	char tmp[64] = { 0, }; 
	strcat_s(buf, buf_len, string);
	sprintf_s(tmp, sizeof(tmp), "%Iu", string_value);
	strcat_s(buf, buf_len, tmp);
}

void lc_printf_stats(struct lru_cache *lc, struct lc_element *e){
	char print_lru[512] = { 0, };
	char print_ele[128] = { 0, };

	if (lc){
		if (lc->name)
			sprintf_s(print_lru, sizeof(print_lru), "name=%s ", lc->name);
		if (lc->nr_elements)
			private_strcat(print_lru, sizeof(print_lru), " nr_elements= ", lc->nr_elements);
		if (lc->max_pending_changes)
			private_strcat(print_lru, sizeof(print_lru), " max_pending_changes= ", lc->max_pending_changes);
		if (lc->pending_changes)
			private_strcat(print_lru, sizeof(print_lru), " pending_changes= ", lc->pending_changes);
		if (lc->used){
			private_strcat(print_lru, sizeof(print_lru), " used= ", lc->used);
			private_strcat(print_lru, sizeof(print_lru), " hits= ", lc->hits);
			private_strcat(print_lru, sizeof(print_lru), " misses= ", lc->misses);
			private_strcat(print_lru, sizeof(print_lru), " starving= ", lc->starving);
			private_strcat(print_lru, sizeof(print_lru), " locked= ", lc->locked);
			private_strcat(print_lru, sizeof(print_lru), " changed= ", lc->changed);
		}
		if (lc->flags)
			private_strcat(print_lru, sizeof(print_lru), " flags= ", lc->flags);
		WDRBD_FATAL("lru : %s\n", print_lru);
	}

	if (e){
		if (e->lc_index)
			sprintf_s(print_ele, sizeof(print_ele), "lc_index=%u ", e->lc_index);
		if (e->refcnt)
			private_strcat(print_ele, sizeof(print_ele), " refcnt= ", e->refcnt);
		if (e->lc_number)
			private_strcat(print_ele, sizeof(print_ele), " lc_number= ", e->lc_number);
		if (e->lc_new_number)
			private_strcat(print_ele, sizeof(print_ele), " lc_new_number= ", e->lc_new_number);

		WDRBD_FATAL("element : %s\n", print_ele);
	}
}
#endif 


/* this is developers aid only.
 * it catches concurrent access (lack of locking on the users part) */
#ifdef WIN_AL_BUG_ON
#define PARANOIA_ENTRY() do {		\
	AL_BUG_ON(!lc, "!lc", (false,false), (false,false));			\
	if(lc == NULL) break;	\
	AL_BUG_ON(!lc->nr_elements, "!lc->nr_elements", lc,  (false,false));	\
	AL_BUG_ON(test_and_set_bit(__LC_PARANOIA, &lc->flags), "test_and_set_bit(__LC_PARANOIA, &lc->flags)", lc,  (false,false)); \
	} while (false,false)
#else 
#define PARANOIA_ENTRY() do {		\
	BUG_ON(!lc);			\
	if(lc == NULL) break;	\
	BUG_ON(!lc->nr_elements);	\
	BUG_ON(test_and_set_bit(__LC_PARANOIA, &lc->flags)); \
		} while (0)
#endif 


#ifdef _WIN32
#define RETURN_VOID()     do { \
	clear_bit_unlock(__LC_PARANOIA, &lc->flags); \
	return; } while (false,false)
#endif

#ifdef _WIN32
#define RETURN(x)     do { \
	clear_bit_unlock(__LC_PARANOIA, &lc->flags); \
	return x ; } while (false,false)
#else
#define RETURN(x...)     do { \
	clear_bit_unlock(__LC_PARANOIA, &lc->flags); \
	return x ; } while (0)
#endif
/* BUG() if e is not one of the elements tracked by lc */
#ifdef WIN_AL_BUG_ON
#define PARANOIA_LC_ELEMENT(lc, e) do {	\
	if (lc == NULL) break;		\
	struct lru_cache *lc_ = (lc);	\
	struct lc_element *e_ = (e);	\
	unsigned i = e_->lc_index;	\
	AL_BUG_ON(i >= lc_->nr_elements, "i >= lc_->nr_elements", lc, e);	\
	AL_BUG_ON(lc_->lc_element[i] != e_, "lc_->lc_element[i] != e_", lc, e); } while (false,false)
#else 
#define PARANOIA_LC_ELEMENT(lc, e) do {	\
	struct lru_cache *lc_ = (lc);	\
	struct lc_element *e_ = (e);	\
	unsigned i = e_->lc_index;	\
	BUG_ON(i >= lc_->nr_elements);	\
	BUG_ON(lc_->lc_element[i] != e_); } while (0)
#endif 

/* We need to atomically
 *  - try to grab the lock (set LC_LOCKED)
 *  - only if there is no pending transaction
 *    (neither LC_DIRTY nor LC_STARVING is set)
 * Because of PARANOIA_ENTRY() above abusing lc->flags as well,
 * it is not sufficient to just say
 *	return 0 == cmpxchg(&lc->flags, 0, LC_LOCKED);
 */
int lc_try_lock(struct lru_cache *lc)
{
	unsigned long val;
	do {
#ifdef _WIN32
		val = atomic_cmpxchg((atomic_t *)&lc->flags, 0, LC_LOCKED);
#else
		val = cmpxchg(&lc->flags, 0, LC_LOCKED);
#endif
	} while (unlikely (val == LC_PARANOIA));
	/* Spin until no-one is inside a PARANOIA_ENTRY()/RETURN() section. */
	return 0 == val;
#if 0
	/* Alternative approach, spin in case someone enters or leaves a
	 * PARANOIA_ENTRY()/RETURN() section. */
	unsigned long old, new, val;
	do {
		old = lc->flags & LC_PARANOIA;
		new = old | LC_LOCKED;
		val = cmpxchg(&lc->flags, old, new);
	} while (unlikely (val == (old ^ LC_PARANOIA)));
	return old == val;
#endif
}

/**
 * lc_create - prepares to track objects in an active set
 * @name: descriptive name only used in lc_seq_printf_stats and lc_seq_dump_details
 * @max_pending_changes: maximum changes to accumulate until a transaction is required
 * @e_count: number of elements allowed to be active simultaneously
 * @e_size: size of the tracked objects
 * @e_off: offset to the &struct lc_element member in a tracked object
 *
 * Returns a pointer to a newly initialized struct lru_cache on success,
 * or NULL on (allocation) failure.
 */
#ifdef _WIN32
struct lru_cache *lc_create(const char *name, PNPAGED_LOOKASIDE_LIST cache,
		unsigned max_pending_changes,
		unsigned e_count, size_t e_size, size_t e_off)
#else
struct lru_cache *lc_create(const char *name, struct kmem_cache *cache,
		unsigned max_pending_changes,
		unsigned e_count, size_t e_size, size_t e_off)
#endif
{
	struct hlist_head *slot = NULL;
	struct lc_element **element = NULL;
	struct lru_cache *lc;
	struct lc_element *e;
#ifndef _WIN32
	unsigned cache_obj_size = kmem_cache_size(cache);
#endif
	unsigned i;
#ifndef _WIN32
	WARN_ON(cache_obj_size < e_size);
	if (cache_obj_size < e_size)
		return NULL;
#endif
	/* e_count too big; would probably fail the allocation below anyways.
	 * for typical use cases, e_count should be few thousand at most. */
	if (e_count > LC_MAX_ACTIVE)
		return NULL;

#ifdef _WIN32
	slot = (struct hlist_head *)ExAllocatePoolWithTag(NonPagedPool,
		e_count * sizeof(struct hlist_head), 'F4DW');
	if (!slot)
		goto out_fail;
	RtlZeroMemory(slot, e_count * sizeof(struct hlist_head));
	element = (struct lc_element **)ExAllocatePoolWithTag(NonPagedPool,
		e_count * sizeof(struct lc_element *), '05DW');
	if (!element)
		goto out_fail;
	RtlZeroMemory(element, e_count * sizeof(struct lc_element *));
	lc = (struct lru_cache *)ExAllocatePoolWithTag(NonPagedPool,
		sizeof(struct lru_cache), '15DW');
	if (!lc)
		goto out_fail;
	RtlZeroMemory(lc, sizeof(struct lru_cache));
#else
	slot = kcalloc(e_count, sizeof(struct hlist_head), GFP_KERNEL);
	if (!slot)
		goto out_fail;
	element = kzalloc(e_count * sizeof(struct lc_element *), GFP_KERNEL);
	if (!element)
		goto out_fail;

	lc = kzalloc(sizeof(*lc), GFP_KERNEL);
	if (!lc)
		goto out_fail;
#endif

	INIT_LIST_HEAD(&lc->in_use);
	INIT_LIST_HEAD(&lc->lru);
	INIT_LIST_HEAD(&lc->free);
	INIT_LIST_HEAD(&lc->to_be_changed);

	lc->name = name;
	lc->element_size = e_size;
	lc->element_off = e_off;
	lc->nr_elements = e_count;
	lc->max_pending_changes = max_pending_changes;
	lc->lc_cache = cache;
	lc->lc_element = element;
	lc->lc_slot = slot;

	/* preallocate all objects */
	for (i = 0; i < e_count; i++) {
#ifdef _WIN32
		UCHAR* p = (UCHAR*)ExAllocateFromNPagedLookasideList(cache);
		if (!p) break;
#else
		unsigned char *p = kmem_cache_alloc(cache, GFP_KERNEL);
		if (!p)
			break;
#endif
		memset(p, 0, lc->element_size);
        e = (struct lc_element*)(p + e_off);
		e->lc_index = i;
		e->lc_number = LC_FREE;
		e->lc_new_number = LC_FREE;
		list_add(&e->list, &lc->free);
		element[i] = e;
	}
	if (i == e_count)
		return lc;

	/* else: could not allocate all elements, give up */
	for (i--; i; i--) {
#ifdef _WIN32
		UCHAR* p = (UCHAR*)element[i];
		ExFreeToNPagedLookasideList(cache, p - e_off);
#else
		void *p = element[i];
		kmem_cache_free(cache, (unsigned char *)p - e_off);
#endif
	}
	kfree(lc);
out_fail:
	kfree(element);
	kfree(slot);
	return NULL;
}

static void lc_free_by_index(struct lru_cache *lc, unsigned i)
{
	void *p = lc->lc_element[i];	
	WARN_ON(!p);
	if (p) {
#ifdef _WIN32
		p = (UCHAR*)p - lc->element_off;
        ExFreeToNPagedLookasideList(lc->lc_cache, p);
#else
		p = (unsigned char*)p - lc->element_off;
		kmem_cache_free(lc->lc_cache, p);
#endif
	}
}

/**
 * lc_destroy - frees memory allocated by lc_create()
 * @lc: the lru cache to destroy
 */
void lc_destroy(struct lru_cache *lc)
{
	unsigned i;
	if (!lc)
		return;
	for (i = 0; i < lc->nr_elements; i++)
		lc_free_by_index(lc, i);
	kfree(lc->lc_element);
	kfree(lc->lc_slot);
	kfree(lc);
}

/**
 * lc_reset - does a full reset for @lc and the hash table slots.
 * @lc: the lru cache to operate on
 *
 * It is roughly the equivalent of re-allocating a fresh lru_cache object,
 * basically a short cut to lc_destroy(lc); lc = lc_create(...);
 */
void lc_reset(struct lru_cache *lc)
{
	unsigned i;

	INIT_LIST_HEAD(&lc->in_use);
	INIT_LIST_HEAD(&lc->lru);
	INIT_LIST_HEAD(&lc->free);
	INIT_LIST_HEAD(&lc->to_be_changed);
	lc->used = 0;
	lc->hits = 0;
	lc->misses = 0;
	lc->starving = 0;
	lc->locked = 0;
	lc->changed = 0;
	lc->pending_changes = 0;
	lc->flags = 0;
	memset(lc->lc_slot, 0, sizeof(struct hlist_head) * lc->nr_elements);

	for (i = 0; i < lc->nr_elements; i++) {
		struct lc_element *e = lc->lc_element[i];
		void *p = e;
#ifdef _WIN32
		p = (UCHAR*)p - lc->element_off;
#else
		p = (unsigned char*)p - lc->element_off;
#endif
		memset(p, 0, lc->element_size);
		/* re-init it */
		e->lc_index = i;
		e->lc_number = LC_FREE;
		e->lc_new_number = LC_FREE;
		list_add(&e->list, &lc->free);
	}
}

/**
 * lc_seq_printf_stats - print stats about @lc into @seq
 * @seq: the seq_file to print into
 * @lc: the lru cache to print statistics of
 */
void lc_seq_printf_stats(struct seq_file *seq, struct lru_cache *lc)
{
	/* NOTE:
	 * total calls to lc_get are
	 * (starving + hits + misses)
	 * misses include "locked" count (update from an other thread in
	 * progress) and "changed", when this in fact lead to an successful
	 * update of the cache.
	 */
#if defined(_WIN64)
	seq_printf(seq, "\t%s: used:%u/%u hits:%lu misses:%lu starving:%lu locked:%lu changed:%lu\n\n",
		   lc->name, lc->used, lc->nr_elements,
		   lc->hits, lc->misses, lc->starving, lc->locked, lc->changed);
#else
	seq_printf(seq, "\t%s: used:%u/%u hits:%lu misses:%lu starving:%lu locked:%lu changed:%lu\n",
		   lc->name, lc->used, lc->nr_elements,
		   lc->hits, lc->misses, lc->starving, lc->locked, lc->changed);
#endif
}

static struct hlist_head *lc_hash_slot(struct lru_cache *lc, unsigned int enr)
{
	return  lc->lc_slot + (enr % lc->nr_elements);
}


static struct lc_element *__lc_find(struct lru_cache *lc, unsigned int enr,
		bool include_changing)
{
	struct lc_element *e;

#ifdef _WIN32
	if (!lc ||
		!lc->nr_elements)
	{
		WDRBD_ERROR("al is inaccessible, it could be not initialized or destroyed.\n");
		return NULL;
	}
#else
	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);
#endif

#ifndef _WIN32
	hlist_for_each_entry(e, lc_hash_slot(lc, enr), colision) {
#else
	hlist_for_each_entry(struct lc_element, e, lc_hash_slot(lc, enr), colision) {
#endif
		/* "about to be changed" elements, pending transaction commit,
		 * are hashed by their "new number". "Normal" elements have
		 * lc_number == lc_new_number. */
		if (e->lc_new_number != enr)
			continue;
		if (e->lc_new_number == e->lc_number || include_changing)
			return e;
		break;
	}
	return NULL;
}

/**
 * lc_find - find element by label, if present in the hash table
 * @lc: The lru_cache object
 * @enr: element number
 *
 * Returns the pointer to an element, if the element with the requested
 * "label" or element number is present in the hash table,
 * or NULL if not found. Does not change the refcnt.
 * Ignores elements that are "about to be used", i.e. not yet in the active
 * set, but still pending transaction commit.
 */
struct lc_element *lc_find(struct lru_cache *lc, unsigned int enr)
{
	return __lc_find(lc, enr, 0);
}

/**
 * lc_is_used - find element by label
 * @lc: The lru_cache object
 * @enr: element number
 *
 * Returns true, if the element with the requested "label" or element number is
 * present in the hash table, and is used (refcnt > 0).
 * Also finds elements that are not _currently_ used but only "about to be
 * used", i.e. on the "to_be_changed" list, pending transaction commit.
 */
bool lc_is_used(struct lru_cache *lc, unsigned int enr)
{
	struct lc_element *e = __lc_find(lc, enr, 1);
	return e && e->refcnt;
}

/**
 * lc_del - removes an element from the cache
 * @lc: The lru_cache object
 * @e: The element to remove
 *
 * @e must be unused (refcnt == 0). Moves @e from "lru" to "free" list,
 * sets @e->enr to %LC_FREE.
 */
void lc_del(struct lru_cache *lc, struct lc_element *e)
{
	if (lc == NULL)
		return;

	PARANOIA_ENTRY();
	PARANOIA_LC_ELEMENT(lc, e);
#ifdef WIN_AL_BUG_ON
	AL_BUG_ON(e->refcnt, "e->refcnt", lc, e);
#else 
	BUG_ON(e->refcnt);
#endif 
	e->lc_number = e->lc_new_number = LC_FREE;
	hlist_del_init(&e->colision);
	list_move(&e->list, &lc->free);
#ifdef _WIN32
	RETURN_VOID();
#else
	RETURN();
#endif
}

static struct lc_element *lc_prepare_for_change(struct lru_cache *lc, unsigned new_number)
{
	struct list_head *n;
	struct lc_element *e;

	if (lc == NULL)
		return NULL;
	if (!list_empty(&lc->free))
		n = lc->free.next;
	else if (!list_empty(&lc->lru))
		n = lc->lru.prev;
	else
		return NULL;

	e = list_entry(n, struct lc_element, list);
	PARANOIA_LC_ELEMENT(lc, e);

	e->lc_new_number = new_number;
	if (!hlist_unhashed(&e->colision))
		__hlist_del(&e->colision);
	hlist_add_head(&e->colision, lc_hash_slot(lc, new_number));
	list_move(&e->list, &lc->to_be_changed);

	return e;
}

static int lc_unused_element_available(struct lru_cache *lc)
{
	if (!list_empty(&lc->free))
		return 1; /* something on the free list */
	if (!list_empty(&lc->lru))
		return 1;  /* something to evict */

	return 0;
}

/* used as internal flags to __lc_get */
enum {
	LC_GET_MAY_CHANGE = 1,
	LC_GET_MAY_USE_UNCOMMITTED = 2,
};

static struct lc_element *__lc_get(struct lru_cache *lc, unsigned int enr, unsigned int flags)
{
	struct lc_element *e;
	if (lc == NULL)
		return NULL;

	PARANOIA_ENTRY();
	if (test_bit(__LC_STARVING, &lc->flags)) {
		++lc->starving;
		RETURN(NULL);
	}

	e = __lc_find(lc, enr, 1);
	/* if lc_new_number != lc_number,
	 * this enr is currently being pulled in already,
	 * and will be available once the pending transaction
	 * has been committed. */
	if (e) {
		if (e->lc_new_number != e->lc_number) {
			/* It has been found above, but on the "to_be_changed"
			 * list, not yet committed.  Don't pull it in twice,
			 * wait for the transaction, then try again...
			 */
			if (!(flags & LC_GET_MAY_USE_UNCOMMITTED))
				RETURN(NULL);
			/* ... unless the caller is aware of the implications,
			 * probably preparing a cumulative transaction. */
			++e->refcnt;
			++lc->hits;
			RETURN(e);
		}
		/* else: lc_new_number == lc_number; a real hit. */
		++lc->hits;
		if (e->refcnt++ == 0)
			lc->used++;
		list_move(&e->list, &lc->in_use); /* Not evictable... */
		RETURN(e);
	}
	/* e == NULL */

	++lc->misses;
	if (!(flags & LC_GET_MAY_CHANGE))
		RETURN(NULL);

	/* To avoid races with lc_try_lock(), first, mark us dirty
	 * (using test_and_set_bit, as it implies memory barriers), ... */
	test_and_set_bit(__LC_DIRTY, &lc->flags);

	/* ... only then check if it is locked anyways. If lc_unlock clears
	 * the dirty bit again, that's not a problem, we will come here again.
	 */
	if (test_bit(__LC_LOCKED, &lc->flags)) {
		++lc->locked;
		RETURN(NULL);
	}

	/* In case there is nothing available and we can not kick out
	 * the LRU element, we have to wait ...
	 */
	if (!lc_unused_element_available(lc)) {
		set_bit(__LC_STARVING, &lc->flags);
		RETURN(NULL);
	}

	/* It was not present in the active set.  We are going to recycle an
	 * unused (or even "free") element, but we won't accumulate more than
	 * max_pending_changes changes.  */
	if (lc->pending_changes >= lc->max_pending_changes)
		RETURN(NULL);

	e = lc_prepare_for_change(lc, enr);
	if (e == NULL)
		RETURN(NULL);

#ifdef WIN_AL_BUG_ON
	AL_BUG_ON(!e, "!e", lc, e);
#else 
	BUG_ON(!e);
#endif 
	clear_bit(__LC_STARVING, &lc->flags);
#ifdef WIN_AL_BUG_ON
	AL_BUG_ON(++e->refcnt != 1, "++e->refcnt != 1", lc, e);
#else 
	BUG_ON(++e->refcnt != 1);
#endif 
	lc->used++;
	lc->pending_changes++;

	RETURN(e);
}

/**
 * lc_get - get element by label, maybe change the active set
 * @lc: the lru cache to operate on
 * @enr: the label to look up
 *
 * Finds an element in the cache, increases its usage count,
 * "touches" and returns it.
 *
 * In case the requested number is not present, it needs to be added to the
 * cache. Therefore it is possible that an other element becomes evicted from
 * the cache. In either case, the user is notified so he is able to e.g. keep
 * a persistent log of the cache changes, and therefore the objects in use.
 *
 * Return values:
 *  NULL
 *     The cache was marked %LC_STARVING,
 *     or the requested label was not in the active set
 *     and a changing transaction is still pending (@lc was marked %LC_DIRTY).
 *     Or no unused or free element could be recycled (@lc will be marked as
 *     %LC_STARVING, blocking further lc_get() operations).
 *
 *  pointer to the element with the REQUESTED element number.
 *     In this case, it can be used right away
 *
 *  pointer to an UNUSED element with some different element number,
 *          where that different number may also be %LC_FREE.
 *
 *          In this case, the cache is marked %LC_DIRTY,
 *          so lc_try_lock() will no longer succeed.
 *          The returned element pointer is moved to the "to_be_changed" list,
 *          and registered with the new element number on the hash collision chains,
 *          so it is possible to pick it up from lc_is_used().
 *          Up to "max_pending_changes" (see lc_create()) can be accumulated.
 *          The user now should do whatever housekeeping is necessary,
 *          typically serialize on lc_try_lock_for_transaction(), then call
 *          lc_committed(lc) and lc_unlock(), to finish the change.
 *
 * NOTE: The user needs to check the lc_number on EACH use, so he recognizes
 *       any cache set change.
 */
struct lc_element *lc_get(struct lru_cache *lc, unsigned int enr)
{
	return __lc_get(lc, enr, LC_GET_MAY_CHANGE);
}

/**
 * lc_get_cumulative - like lc_get; also finds to-be-changed elements
 * @lc: the lru cache to operate on
 * @enr: the label to look up
 *
 * Unlike lc_get this also returns the element for @enr, if it is belonging to
 * a pending transaction, so the return values are like for lc_get(),
 * plus:
 *
 * pointer to an element already on the "to_be_changed" list.
 * 	In this case, the cache was already marked %LC_DIRTY.
 *
 * Caller needs to make sure that the pending transaction is completed,
 * before proceeding to actually use this element.
 */
struct lc_element *lc_get_cumulative(struct lru_cache *lc, unsigned int enr)
{
	return __lc_get(lc, enr, LC_GET_MAY_CHANGE|LC_GET_MAY_USE_UNCOMMITTED);
}

/**
 * lc_try_get - get element by label, if present; do not change the active set
 * @lc: the lru cache to operate on
 * @enr: the label to look up
 *
 * Finds an element in the cache, increases its usage count,
 * "touches" and returns it.
 *
 * Return values:
 *  NULL
 *     The cache was marked %LC_STARVING,
 *     or the requested label was not in the active set
 *
 *  pointer to the element with the REQUESTED element number.
 *     In this case, it can be used right away
 */
struct lc_element *lc_try_get(struct lru_cache *lc, unsigned int enr)
{
	return __lc_get(lc, enr, 0);
}

/**
 * lc_committed - tell @lc that pending changes have been recorded
 * @lc: the lru cache to operate on
 *
 * User is expected to serialize on explicit lc_try_lock_for_transaction()
 * before the transaction is started, and later needs to lc_unlock() explicitly
 * as well.
 */
void lc_committed(struct lru_cache *lc)
{
	struct lc_element *e, *tmp;

	if (lc == NULL)
		return;
	PARANOIA_ENTRY();
#ifndef _WIN32
	list_for_each_entry_safe(e, tmp, &lc->to_be_changed, list) {
#else
	list_for_each_entry_safe(struct lc_element, e, tmp, &lc->to_be_changed, list) {
#endif
		/* count number of changes, not number of transactions */
		++lc->changed;
		e->lc_number = e->lc_new_number;
		list_move(&e->list, &lc->in_use);
	}
	lc->pending_changes = 0;
#ifdef _WIN32
	RETURN_VOID();
#else
	RETURN();
#endif
}


/**
 * lc_put - give up refcnt of @e
 * @lc: the lru cache to operate on
 * @e: the element to put
 *
 * If refcnt reaches zero, the element is moved to the lru list,
 * and a %LC_STARVING (if set) is cleared.
 * Returns the new (post-decrement) refcnt.
 */
int lc_put(struct lru_cache *lc, struct lc_element *e)
{
	PARANOIA_ENTRY();
	if (lc == NULL || e == NULL)
		return -EINVAL;

	PARANOIA_LC_ELEMENT(lc, e);
#ifdef WIN_AL_BUG_ON	
	AL_BUG_ON(e->refcnt == 0, "e->refcnt == 0", lc, e);
	AL_BUG_ON(e->lc_number != e->lc_new_number, "e->lc_number != e->lc_new_number", lc, e);
#else 	
	BUG_ON(e->refcnt == 0);
	BUG_ON(e->lc_number != e->lc_new_number);
#endif	
	if (--e->refcnt == 0) {
		/* move it to the front of LRU. */
		list_move(&e->list, &lc->lru);
		lc->used--;
		clear_bit_unlock(__LC_STARVING, &lc->flags);
	}
	RETURN(e->refcnt);
}

/**
 * lc_element_by_index
 * @lc: the lru cache to operate on
 * @i: the index of the element to return
 */
struct lc_element *lc_element_by_index(struct lru_cache *lc, unsigned i)
{
#ifdef WIN_AL_BUG_ON
	if (lc == NULL)
		return NULL;
	AL_BUG_ON(i >= lc->nr_elements, "i >= lc->nr_elements", lc, NULL);
	AL_BUG_ON(lc->lc_element[i] == NULL, "lc->lc_element[i] == NULL", lc, NULL);
	if (lc->lc_element[i] == NULL)
		return NULL;

	AL_BUG_ON(lc->lc_element[i]->lc_index != i, "lc->lc_element[i]->lc_index != i", lc, lc->lc_element[i]);
#else
	if (lc == NULL)
		return NULL;
	BUG_ON(i >= lc->nr_elements);
	BUG_ON(lc->lc_element[i] == NULL);
	BUG_ON(lc->lc_element[i]->lc_index != i);
#endif 
	return lc->lc_element[i];
}

/**
 * lc_index_of
 * @lc: the lru cache to operate on
 * @e: the element to query for its index position in lc->element
 */
unsigned int lc_index_of(struct lru_cache *lc, struct lc_element *e)
{
	PARANOIA_LC_ELEMENT(lc, e);
	return e->lc_index;
}

/**
 * lc_set - associate index with label
 * @lc: the lru cache to operate on
 * @enr: the label to set
 * @index: the element index to associate label with.
 *
 * Used to initialize the active set to some previously recorded state.
 */
void lc_set(struct lru_cache *lc, unsigned int enr, int index)
{
	struct lc_element *e;
	struct list_head *lh;

	if (!lc || index < 0 || (unsigned int)index >= lc->nr_elements)
		return;

	e = lc_element_by_index(lc, index);
	if (e == NULL)
		return;
#ifdef WIN_AL_BUG_ON	
	AL_BUG_ON(e->lc_number != e->lc_new_number, "e->lc_number != e->lc_new_number", lc, e);
	AL_BUG_ON(e->refcnt != 0, "e->refcnt != 0", lc, e);
#else
	BUG_ON(e->lc_number != e->lc_new_number);
	BUG_ON(e->refcnt != 0);
#endif

	e->lc_number = e->lc_new_number = enr;
	hlist_del_init(&e->colision);
	if (enr == LC_FREE)
		lh = &lc->free;
	else {
		hlist_add_head(&e->colision, lc_hash_slot(lc, enr));
		lh = &lc->lru;
	}
	list_move(&e->list, lh);
}

/**
 * lc_dump - Dump a complete LRU cache to seq in textual form.
 * @lc: the lru cache to operate on
 * @seq: the &struct seq_file pointer to seq_printf into
 * @utext: user supplied additional "heading" or other info
 * @detail: function pointer the user may provide to dump further details
 * of the object the lc_element is embedded in. May be NULL.
 * Note: a leading space ' ' and trailing newline '\n' is implied.
 */
void lc_seq_dump_details(struct seq_file *seq, struct lru_cache *lc, char *utext,
	     void (*detail) (struct seq_file *, struct lc_element *))
{
	unsigned int nr_elements = lc->nr_elements;
	struct lc_element *e;
	unsigned int i;

	seq_printf(seq, "\tnn: lc_number (new nr) refcnt %s\n ", utext);
	for (i = 0; i < nr_elements; i++) {
		e = lc_element_by_index(lc, i);
		if (e->lc_number != e->lc_new_number)
			seq_printf(seq, "\t%5d: %6d %8d %6d ",
				i, e->lc_number, e->lc_new_number, e->refcnt);
		else
			seq_printf(seq, "\t%5d: %6d %-8s %6d ",
				i, e->lc_number, "-\"-", e->refcnt);
		if (detail)
			detail(seq, e);
		seq_putc(seq, '\n');
	}
}
