package com.mantech.wdrbd.usage;

import java.io.IOException;

import com.google.gdata.util.ServiceException;

public class Main
{
	public static void main(String [] args) throws IOException, ServiceException, InterruptedException
	{
		SystemUtils s = new SystemUtils(args);
		GoogleUtils gUtils = new GoogleUtils();
		SpreadSheetUtils sUtils = new SpreadSheetUtils(gUtils);
		sUtils.AddRow(sUtils.getWorksheet(), s);
	}
}
