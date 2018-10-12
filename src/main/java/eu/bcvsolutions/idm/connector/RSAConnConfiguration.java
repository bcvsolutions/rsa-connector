package eu.bcvsolutions.idm.connector;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * Main configuration class. Here are set all attributes which are needed for connection
 *
 * @author Petr Hanak
 * 
 */
public class RSAConnConfiguration extends AbstractConfiguration {

    // Constants
    public static final String RSA_DOMAIN = "SystemDomain";
    public static final String CONFIG_PROPERTIES_FILE = "config.properties";
    public static final String DATE_FORMAT = "yyyy/MM/dd";
    public static final Integer SEARCH_LIMIT_DEFAULT = 100000;
    public static final String ENABLED = "ENABLED";
    public static final String PIN = "PIN";
    public static final String PHONE = "PHONE";
    
    // Configuration    
    private String SecurityDomain = null;
    private String identitySource = null;
    private String username = "";
    private GuardedString password;
    private String stringPassword;
    private String cmdClientUser = null;
    private String cmdClientPassword = null;
    
	@ConfigurationProperty(order = 1, displayMessageKey = "SecurityDomain.display",
			helpMessageKey = "SecurityDomain.help",
			required = false, confidential = false)
	public String getSecurityDomain() {
		return SecurityDomain;
	}
	public void setSecurityDomain(String SecurityDomain) {
		this.SecurityDomain = SecurityDomain;
	}
	
    @ConfigurationProperty(order = 2, displayMessageKey = "IdentitySource.display",
    		helpMessageKey = "IdentitySource.help",
    		required = false, confidential = false)
	public String getIdentitySource() {
		return identitySource;
	}
	public void setIdentitySource(String identitySource) {
		this.identitySource = identitySource;
	}
    
    @ConfigurationProperty(displayMessageKey = "username.display",
    		helpMessageKey = "username.help", order = 3,
    		required = false, confidential = false)
    public String getUsername() {
    	return username;
    }
    public void setUsername(String username) {
    	this.username = username;
    }
    
    @ConfigurationProperty(displayMessageKey = "password.display",
            helpMessageKey = "password.help", order = 4,
            required = false, confidential = true)
    public GuardedString getPassword() {
        return password;
    }
    public void setPassword(GuardedString password) {
        this.password = password;
    }
    
    @ConfigurationProperty(displayMessageKey = "strpassword.display",
    		helpMessageKey = "strpassword.help", order = 5,
    		required = false, confidential = false)
    public String getStringPassword() {
    	return stringPassword;
    }
    public void setStringPassword(String password) {
    	this.stringPassword = password;
    }
    
    
    @ConfigurationProperty(order = 6, displayMessageKey = "CmdclientUser.display",
            helpMessageKey = "CmdclientUser.help",
            required = false, confidential = false)
    public String getCmdclientUser() {
        return cmdClientUser;
    }
    public void setCmdclientUser(String CmdclientUser) {
        this.cmdClientUser = CmdclientUser;
    }
    
    @ConfigurationProperty(order = 7, displayMessageKey = "CmdclientPassword.display",
    		helpMessageKey = "CmdclientPassword.help",
    		required = false, confidential = false)
    public String getCmdclientPassword() {
    	return cmdClientPassword;
    }
    public void setCmdclientPassword(String CmdclientUser) {
    	this.cmdClientPassword = CmdclientUser;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(username)) {
            throw new ConfigurationException("Username must not be blank!");
        }
    }
}
