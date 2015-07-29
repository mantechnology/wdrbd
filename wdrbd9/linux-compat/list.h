#ifndef __LIST_H__
#define __LIST_H__


#ifdef CONFIG_ILLEGAL_POINTER_VALUE
#define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)
#else
#define POISON_POINTER_DELTA		0
#endif

#define LIST_POISON1			0 
#define LIST_POISON2			0 

struct list_head {
	struct list_head *next, *prev;
};

extern void list_del_init(struct list_head *entry);

#define list_entry(ptr, type, member)		container_of(ptr, type, member)
#define list_first_entry(ptr, type, member)	list_entry((ptr)->next, type, member)

#define LIST_HEAD_INIT(name)			{ &(name), &(name) }
#define LIST_HEAD(name)				struct list_head name = LIST_HEAD_INIT(name)

static __inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static __inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static __inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static __inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static __inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static __inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static __inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	extern long *g_mdev_ptr, g_mdev_ptr_test; 
	__list_add(new, head->prev, head);
}

/*
* Insert a new entry between two known consecutive entries.
*
* This is only for internal list manipulation where we know
* the prev/next entries already!
*/
static __inline void __list_add_rcu(struct list_head * new,
struct list_head * prev, struct list_head * next)
{
    new->next = next;
    new->prev = prev;
    //smp_wmb();
    next->prev = new;
    prev->next = new;
}

/**
* list_add_rcu - add a new entry to rcu-protected list
* @new: new entry to be added
* @head: list head to add it after
*
* Insert a new entry after the specified head.
* This is good for implementing stacks.
*
* The caller must take whatever precautions are necessary
* (such as holding appropriate locks) to avoid racing
* with another list-mutation primitive, such as list_add_rcu()
* or list_del_rcu(), running on this same list.
* However, it is perfectly legal to run concurrently with
* the _rcu list-traversal primitives, such as
* list_for_each_entry_rcu().
*/
// kmpak 20150729 wdrbd9에서 신규 추가
static __inline void list_add_rcu(struct list_head *new, struct list_head *head)
{
    __list_add_rcu(new, head, head->next);
}

static __inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

static __inline void list_move_tail(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

static __inline void __list_splice(const struct list_head *list, struct list_head *prev, struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;
	last->next = next;
	next->prev = last;
}

static __inline void list_splice_init(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head, head->next);
		INIT_LIST_HEAD(list);
	}
}

/**
* list_splice_tail_init - join two lists and reinitialise the emptied list
* @list: the new list to add.
* @head: the place to add it in the first list.
*
* Each of the lists is a queue.
* The list at @list is reinitialised
*/
static __inline void list_splice_tail_init(struct list_head *list,
                        struct list_head *head)
{
    if (!list_empty(list))
    {
        __list_splice(list, head->prev, head);
        INIT_LIST_HEAD(list);
    }
}

static __inline int list_empty_careful(const struct list_head *head)
{
     struct list_head *next = head->next;
     return (next == head) && (next == head->prev);
}

#ifdef _WIN32_CHECK
#define prefetch(_addr)		(_addr)
#define list_for_each_entry_rcu(type, pos, head, member) \
	for (pos = list_entry_rcu((head)->next, type, member); \
		prefetch(pos->member.next), &pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, type, member))
#else
#define list_for_each_entry_rcu(pos, head, member) \
	for (;;)
#endif

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(type, pos, head, member) \
	for (pos = list_entry((head)->next, type, member);	\
			&pos->member != (head); 	\
			pos = list_entry(pos->member.next, type, member))

#define list_for_each_entry_safe_from(type, pos, n, head, member) 			\
	for (n = list_entry(pos->member.next, type, member);		\
			&pos->member != (head);						\
			pos = n, n = list_entry(n->member.next, type, member))

#define list_for_each_entry_safe(type, pos, n, head, member)                  \
		for (pos = list_entry((head)->next, type, member),      \
					n = list_entry(pos->member.next, type, member); \
				&pos->member != (head);                                    \
				pos = n, n = list_entry(n->member.next, type, member))
#endif _LIST_H__
