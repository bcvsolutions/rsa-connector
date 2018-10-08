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
    
    // Configuration    
    private String username = "";
    private GuardedString password;
    private String stringPassword;
    /**
     * The RSA Security Domain to use with this Connector instance
     */
    private String SecurityDomain = null;
    /** 
     * User ID for process-level Authentication.
     */ 
    private String cmdClientUser = null;
    private String cmdClientPassword = null;
    
    private String identitySource = null;
    
    @ConfigurationProperty(order = 1, displayMessageKey = "CmdclientUser.display",
            helpMessageKey = "CmdclientUser.help",
            required = false, confidential = false)
    public String getCmdclientUser() {
        return cmdClientUser;
    }
    public void setCmdclientUser(String CmdclientUser) {
        this.cmdClientUser = CmdclientUser;
    }
    
    @ConfigurationProperty(order = 1, displayMessageKey = "CmdclientPassword.display",
    		helpMessageKey = "CmdclientPassword.help",
    		required = false, confidential = false)
    public String getCmdclientPassword() {
    	return cmdClientPassword;
    }
    public void setCmdclientPassword(String CmdclientUser) {
    	this.cmdClientPassword = CmdclientUser;
    }
    
    @ConfigurationProperty(order = 1, displayMessageKey = "IdentitySource.display",
    helpMessageKey = "IdentitySource.help",
    required = false, confidential = false)
	public String getIdentitySource() {
		return identitySource;
	}
	public void setIdentitySource(String identitySource) {
		this.identitySource = identitySource;
	}
	
	@ConfigurationProperty(order = 1, displayMessageKey = "SecurityDomain.display",
			helpMessageKey = "SecurityDomain.help",
			required = false, confidential = false)
	public String getSecurityDomain() {
		return SecurityDomain;
	}
	public void setSecurityDomain(String SecurityDomain) {
		this.SecurityDomain = SecurityDomain;
	}
    
    @ConfigurationProperty(displayMessageKey = "username.display",
    		helpMessageKey = "username.help", order = 2)
    public String getUsername() {
    	return username;
    }
    
    public void setUsername(String username) {
    	this.username = username;
    }
    
    @ConfigurationProperty(displayMessageKey = "password.display",
            helpMessageKey = "password.help", order = 3)
    public GuardedString getPassword() {
        return password;
    }

    public void setPassword(GuardedString password) {
        this.password = password;
    }
    
    @ConfigurationProperty(displayMessageKey = "strpassword.display",
    		helpMessageKey = "strpassword.help", order = 4)
    public String getStringPassword() {
    	return stringPassword;
    }
    
    public void setStringPassword(String password) {
    	this.stringPassword = password;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(username)) {
            throw new ConfigurationException("Username must not be blank!");
        }
    }
}
