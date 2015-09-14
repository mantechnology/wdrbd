package com.mantech.wdrbd.usage;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.File;
import com.google.gdata.data.spreadsheet.ListEntry;
import com.google.gdata.data.spreadsheet.ListFeed;
import com.google.gdata.data.spreadsheet.SpreadsheetEntry;
import com.google.gdata.data.spreadsheet.WorksheetEntry;
import com.google.gdata.data.spreadsheet.WorksheetFeed;
import com.google.gdata.util.ServiceException;

public class SpreadSheetUtils
{
	GoogleUtils gUtils;
	int fileVersion = 0;
	String spreadsheetFileId = "1I3EnYUR_ZTMFXlqLLrdAV00kdqDoPvNG2xcw9V1X8Hc";
	String dataWorksheetTitle = "WDRBDUsageSheet";
	WorksheetEntry wdrbdWorkSheetEntry;
	
	public SpreadSheetUtils(GoogleUtils gUtils)
	{
		this.gUtils = gUtils;
	}
	
	public WorksheetEntry getWorksheet() throws IOException, ServiceException
	{
		File spreadsheetFile = null;
	    try {
	    	Drive.Files.Get getCommand = gUtils.getDriveService().files().get(spreadsheetFileId);
	    	spreadsheetFile = getCommand.execute();
	
		  } catch (IOException e) {
//		  	System.out.println(e.getMessage());
		  	System.exit(1);
		  }
	
		  if (spreadsheetFile == null)
		  {
			  System.exit(1);
		  }
		  
		  SpreadsheetEntry spreadsheetEntry = this.getSpreadsheet(spreadsheetFile);
		  WorksheetEntry worksheetEntry = this.getDataWorksheet(spreadsheetEntry);
		  return worksheetEntry;
	}
	
	private SpreadsheetEntry getSpreadsheet(File file) throws IOException, ServiceException {
		
		String spreadsheetURL = "https://spreadsheets.google.com/feeds/spreadsheets/" + file.getId();

//		System.out.println("spreadsheetURL : " + spreadsheetURL);
        SpreadsheetEntry spreadsheetEntry = gUtils.spreadsheetService.getEntry(new URL(spreadsheetURL), SpreadsheetEntry.class);
        return spreadsheetEntry;
    } 
	
	private WorksheetEntry getDataWorksheet(SpreadsheetEntry spreadsheetEntry) throws IOException, ServiceException
	{
		WorksheetEntry worksheetEntry = null;
        WorksheetFeed worksheetFeed = gUtils.spreadsheetService.getFeed(spreadsheetEntry.getWorksheetFeedUrl(), WorksheetFeed.class);
        List<WorksheetEntry> worksheets = worksheetFeed.getEntries();
        
        for (WorksheetEntry worksheet: worksheets)
        {
            if (worksheet.getTitle().getPlainText().equalsIgnoreCase(dataWorksheetTitle))
            {
            	worksheetEntry = worksheet;
            }
        }

        return worksheetEntry;
    }
	
	public void AddRow(WorksheetEntry worksheetEntry, SystemUtils s) throws IOException, ServiceException
	{
        URL listFeedUrl = worksheetEntry.getListFeedUrl();
//        ListFeed listFeed = gUtils.getSpreadsheetService().getFeed(listFeedUrl, ListFeed.class);
//        getRows(listFeed);
        saveRow(listFeedUrl, s);
	}
	
	private void saveRow(URL listFeedUrl, SystemUtils s) throws IOException, ServiceException
	{
		ListEntry newRow = new ListEntry();
	    newRow.getCustomElements().setValueLocal("os", s.getOsFriendlyName());
	    newRow.getCustomElements().setValueLocal("wdrbdversion", s.getWdrbdVersion());
	    newRow.getCustomElements().setValueLocal("installeddate", s.getInstalledDate());
	    newRow = gUtils.getSpreadsheetService().insert(listFeedUrl, newRow);
    }

//    private void getRows(ListFeed listFeed)
//    {
//    	for (ListEntry row : listFeed.getEntries())
//    	{
//    		for (String tag : row.getCustomElements().getTags())
//    		{
//    			System.out.print(row.getCustomElements().getValue(tag) + "\t");
//    		}
//    		System.out.println();
//    	}
//    }
	
}
