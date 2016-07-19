package com.mantech.wdrbd.usage;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class SystemUtils
{
	private String osFriendlyName;
	private String wdrbdVersion;
	private String installedDate;
	
	public SystemUtils(String[] args) throws IOException, InterruptedException
	{
		setOsFriendlyName();
		setWdrbdVersion(args);
		setInstalledDate();
	}
	
	static class StreamReader extends Thread
	{
        private InputStream is;
        private StringWriter sw = new StringWriter();
 
        public StreamReader(InputStream is) {
            this.is = is;
        }
 
        public void run() {
            try {
                int c;
                while ((c = is.read()) != -1)
                    sw.write(c);
            } catch (IOException e) { 
            }
        }
 
        public String getResult() {
            return sw.toString();
        }
    }
	
	private String getRegValue(String location, String key) throws IOException, InterruptedException
	{
		Process process = Runtime.getRuntime().exec("reg query " +'"'+ location + "\" /v " + key);
        StreamReader reader = new StreamReader(process.getInputStream());
        reader.start();
        process.waitFor();
        reader.join();
        String[] parsed = reader.getResult().split("REG_SZ");
        return (parsed.length == 1) ? "" : parsed[1].trim() + " ";  
	}
	
	private void setOsFriendlyName() throws IOException, InterruptedException
	{
		String location = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
		String osKey = "ProductName";
		String servicepackKey = "CSDVersion";
		String osName = null;
		String servicePack = null;
		
		osName = getRegValue(location, osKey);
		servicePack = getRegValue(location, servicepackKey);
		
		if (null == osFriendlyName)
		{
			this.osFriendlyName = osName + servicePack  + (null == System.getenv("PROCESSOR_ARCHITEW6432") ? "x86" : "x64");
		}
	}
	
	private void setWdrbdVersion(String[] args)
	{
		if ((null == wdrbdVersion) && (args.length == 0))
		{
			this.wdrbdVersion = "UNKNOWN";
		}
		else
		{
			this.wdrbdVersion = args[0];
		}
	}
	
	private void setInstalledDate()
	{
		// "2015/02/26 13:26";
		if (null == this.installedDate)
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			this.installedDate = dateFormat.format(date);
		}
	}
	
	public String getOsFriendlyName()
	{
		return this.osFriendlyName;
	}
	
	public String getWdrbdVersion()
	{
		return this.wdrbdVersion;
	}
	
	public String getInstalledDate()
	{
		return this.installedDate;
	}
}
