package com.mantech.wdrbd.usage;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.gdata.client.spreadsheet.SpreadsheetService;

public class GoogleUtils
{
	SpreadsheetService spreadsheetService;
	Drive driveService;
	GoogleCredential credential;
	String appName;
	
	public GoogleUtils() throws IOException
	{
		setGoogleAuth();
		this.spreadsheetService = getSpreadsheetService();
		this.driveService = getDriveService();
		this.appName = getAppName();
	}
	
	private void setGoogleAuth() throws IOException
	{
		final List<String> SCOPES = Arrays.asList(
			      "https://www.googleapis.com/auth/drive",
			      "https://spreadsheets.google.com/feeds",
			      "https://docs.google.com/feeds");
		String personalMailAddress = "744051026293-s0qvi4gak7ce9n53up825cdjgvihkrf7@developer.gserviceaccount.com";
		HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
		JsonFactory JSON_FACTORY = new JacksonFactory();
	      
		try {
			credential = new GoogleCredential.Builder().setTransport(HTTP_TRANSPORT).setJsonFactory(JSON_FACTORY)
			          .setServiceAccountId(personalMailAddress)
			          .setTokenServerEncodedUrl("https://accounts.google.com/o/oauth2/token")
			          .setServiceAccountScopes(SCOPES)
			          .setServiceAccountPrivateKeyFromP12File(new File("drbdusage/drbdusage.p12"))
			          .build();
		} catch (GeneralSecurityException | IOException e) {}
		credential.refreshToken();
	}
	
	public SpreadsheetService getSpreadsheetService()
	{
		if (this.spreadsheetService == null)
        {
            this.spreadsheetService = new SpreadsheetService(this.getAppName());
            spreadsheetService.setOAuth2Credentials(credential);
        }
        return this.spreadsheetService;
    }

    public Drive getDriveService()
    {
        if (this.driveService == null)
        {
            this.driveService = new Drive.Builder(new NetHttpTransport(), new JacksonFactory(), credential)
                    .setApplicationName(this.getAppName())
                    .build();
        }
        return this.driveService;
    }
    
    private String getAppName()
    {
    	if (null == this.appName) this.appName = "Mantech-WDRBDUSAGE-v1";
    	return this.appName;
    }
}
