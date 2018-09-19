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
 */
public class RSAConnConfiguration extends AbstractConfiguration {

	private String url = "";
    private String username = "";
    private GuardedString password;
    private String stringPassword;
    
    @ConfigurationProperty(displayMessageKey = "url.display",
            helpMessageKey = "url.help", order = 1)
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
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
