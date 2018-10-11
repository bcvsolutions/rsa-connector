package eu.bcvsolutions.idm.connector;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;

import com.rsa.admin.SearchPrincipalsCommand;
import com.rsa.admin.SearchRealmsCommand;
import com.rsa.admin.data.IdentitySourceDTO;
import com.rsa.admin.data.PrincipalDTO;
import com.rsa.admin.data.RealmDTO;
import com.rsa.admin.data.SecurityDomainDTO;
import com.rsa.command.ClientSession;
import com.rsa.command.CommandException;
import com.rsa.command.CommandTargetPolicy;
import com.rsa.command.Connection;
import com.rsa.command.ConnectionFactory;
import com.rsa.command.InvalidSessionException;
import com.rsa.command.exception.DataNotFoundException;
import com.rsa.command.exception.InsufficientPrivilegeException;
import com.rsa.command.exception.InvalidArgumentException;
import com.rsa.common.search.Filter;

/**
 * Class for connection handling
 *
 * @author Petr Hanak
 * 
 */
public class RSAConnConnection {
	
	   /**
     * An instance of the RSA Configuration
     */
    private RSAConnConfiguration configuration;
    /**
     * An instance of a Connection to the RSA Server
     */
    private ClientSession RSAsession;
    /**
     * The RSA Security Domain
     */
    private final SecurityDomainDTO domain;
    /**
     * The RSA IS Source
     */
    private final IdentitySourceDTO idSource;
    /**
     * Setup logging for the {@link RSAConnConnection}.
     */
    private static final Log logger = Log.getLog(RSAConnConnection.class);
    
    // Connection init
	public RSAConnConnection(RSAConnConfiguration configuration) {
		this.configuration = configuration;
		this.RSAsession = newSession();
        
        // make all commands execute using this target automatically
        CommandTargetPolicy.setDefaultCommandTarget(this.RSAsession);
        
        logger.info("Using session with ID: {0}.", this.RSAsession.getSessionId());
        
        // Fetch the Security Domain DTO and search for the ID Source by querying the RSA Security realm
        // First determine whether the connector was instantiated with a specific Domain ID, else use
        // the default ("SystemDomain").
        String DomainString = null;
        String CfgDomainString = this.configuration.getSecurityDomain();
        if (CfgDomainString == null) 
            DomainString = RSAConnConfiguration.RSA_DOMAIN;
        else {
            logger.info ("Using Security Domain {0}...", CfgDomainString);
            DomainString = CfgDomainString;
        }
        
        SearchRealmsCommand searchRealmCmd = new SearchRealmsCommand();
        searchRealmCmd.setFilter(Filter.equal(RealmDTO.NAME_ATTRIBUTE, DomainString));
        
        logger.info("Searching for RSA SecurityDomain with filter: " + searchRealmCmd.getFilter().toString());

        try {
            searchRealmCmd.execute(RSAsession);
            this.sessionLogout(RSAsession);
        } catch (InsufficientPrivilegeException e) {
            logger.error("Insufficient Privileges to create Principal: " + e.getMessage() + " User ID: " + configuration.getCmdclientUser());
            throw new RuntimeException ("Insufficient Privileges to create Principal", e);
        } catch (DataNotFoundException e) {
            logger.error("Could not find the RSA Security Domain: " + DomainString + " - " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause());
            throw new RuntimeException ("Could not find the RSA Security Domain: ", e);
        } catch (InvalidArgumentException e) {
            logger.error("Invalid Argument for Domain search: " + DomainString + " - " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause());
            throw new RuntimeException ("Invalid Argument for Domain search: ", e);
        } catch (InvalidSessionException e) {
            logger.error("Invalid Session - " + e.getMessage());
            throw new RuntimeException ("Invalid Session", e);
        } catch (CommandException e) {
            logger.error("An exception was thrown by the RSA command: " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause());
            throw new RuntimeException ("An exception was thrown by the RSA command: ", e);
        } 
        
        RealmDTO[] realms = searchRealmCmd.getRealms();
        if (realms.length == 0) {
            // ERROR: TODO: throw new Exception("ERROR: Could not find realm SystemDomain");
            domain = null;
            idSource = null;
            logger.error("Unable to find any RSA Security Realm");
            throw new IllegalArgumentException ("Failed to find the requested RSA Security Domain: " + DomainString + " - with filter: " + searchRealmCmd.getFilter().toString());

        } else {
            domain = realms[0].getTopLevelSecurityDomain();
            logger.info("Found RSA SecurityDomain: " + domain.getName());
            
            // Iterate over Identity Sources to find one by name             
            IdentitySourceDTO[] idSources = realms[0].getIdentitySources();
            String idSourceName = configuration.getIdentitySource();
            int sourceNum = 0;
            for (int i = 0; i < idSources.length; i++) {
            	if (idSources[i].getName().equals(idSourceName)) {
            		sourceNum = i;
            	}
            }
            idSource = idSources[sourceNum];
            logger.info("Found RSA ID Source: " + idSource.getName());
        }
	}
	
    /**
     * Gets the RSA Session object from the connection.
     * 
     * @return a RSA Session object.
     */
    public ClientSession getRSASession () {
        return this.RSAsession;
    }
    /**
     * Gets the RSA ID Source for the current connection
     * 
     * @return An Identity Source object
     */
    public IdentitySourceDTO getIdSource () {
        return this.idSource;
    }
    /**
     * Gets the RSA Security Domain for the current connection
     * @return an instance of a Domain
     */
    public SecurityDomainDTO getDomain () {
        return this.domain;
    }
    
    /**
     * Release internal resources.
     */
    public void dispose() {
        logger.info("Disposing Connection");
        try {
            this.RSAsession.logout();
            logger.info("Successful Logout");
        } catch (CommandException e) {
            logger.info("Failed to Logout of the RSA server. Error: " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause());
        }
        
        this.RSAsession = null;
    }
    
    public void test() {
        // establish a connected session with given credentials
        logger.info("Connection Session ID {0}:", this.RSAsession.getSessionId());
        logger.info("Connection domain name {0}:", this.domain.getName());
        logger.info("Connection ID Source {0}:", this.idSource);
        
//    	final GuardedString password = configuration.getPassword();
    	final String username = configuration.getUsername();
    	final String password = configuration.getStringPassword();
    	
			Connection conn = ConnectionFactory.getConnection("CommandAPIConnection");
			logger.info("Connection factory initialized!");
            // make all commands execute using this target automatically
			// CommandTargetPolicy.setDefaultCommandTarget(RSAsession);
//			logger.info("Connection succeeded: {0}", this.RSAsession.getSessionId());
        
        try {
            // as test, query self to see if there is proper response
            SearchPrincipalsCommand cmd = new SearchPrincipalsCommand();
            cmd.setLimit(RSAConnConfiguration.SEARCH_LIMIT_DEFAULT);
            cmd.setIdentitySourceGuid(getIdSource().getGuid());
            logger.info("Identity Source: " + getIdSource().getName());
            cmd.setSecurityDomainGuid(getDomain().getGuid());
            cmd.setAttributeMask(new String[]{"CORE_ATTRIBUTES"});
            cmd.setFilter(Filter.equal(PrincipalDTO.LOGINUID, configuration.getUsername()));
            cmd.setSearchSubDomains(true);
            
            ClientSession ses = this.newSession();
            cmd.execute(ses);
            this.sessionLogout(ses);
            
            logger.info("Connection Test Successful");
        } catch (Exception e) {
            logger.warn("Connection Test Failed");
            throw new IllegalStateException ("RSA Connection failed", e);
        }
    }
    
    /**
     * Creates and returns a brand new connection (rather than pooled/cached connection).
     * This may be preferable to use with some commands
     * 
     * @return a ClientSession.
     */
    public ClientSession newSession() {
    	ClientSession newSession;
        String username = configuration.getUsername();
    	String password = configuration.getStringPassword();
        logger.info("Creating a new Session");
        
        // establish a connected session with given credentials
        Connection conn = ConnectionFactory.getConnection("CommandAPIConnection"); // "CommandAPIConnection"  // createConfigProperties()
        logger.info ("Connection instantiated. Attempting to login...");
        
//        String PlainPwd = RSAAuthenticationManager8Utils.getPlainPassword(this.configuration.getUserMgrPwd());
        
        try {
            newSession = conn.connect(username, password);
            logger.info("Connection succeeded: {0}", newSession.getSessionId());
        } catch (CommandException e) {
            logger.error("Failed to connect to the RSA server. Error: " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause() 
                         + "\n User: " + username + " - Pwd: " + password);
            throw new org.identityconnectors.framework.common.exceptions.ConnectionFailedException(e);
        }

        return newSession;
    }
    
    /**
     * Creates and returns a brand new connection for cmd client session (rather than pooled/cached connection).
     * This may be preferable to use with some commands
     * 
     * @return a ClientSession.
     */
	public ClientSession newCmdClientSession() {
    	ClientSession newSession;
    	String username = configuration.getCmdclientUser();
    	String password = configuration.getCmdclientPassword();
    	logger.info("Creating a new Session");
    	
    	// establish a connected session with given credentials
    	Connection conn = ConnectionFactory.getConnection("CommandAPIConnection"); // "CommandAPIConnection"  // createConfigProperties()
    	logger.info ("Connection instantiated. Attempting to login...");
    	
//        String PlainPwd = RSAAuthenticationManager8Utils.getPlainPassword(this.configuration.getUserMgrPwd());
    	
    	try {
    		newSession = conn.connect(username, password);
    		logger.info("Connection succeeded: {0}", newSession.getSessionId());
    	} catch (CommandException e) {
    		logger.error("Failed to connect to the RSA server. Error: " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause() 
    		+ "\n User: " + username + " - Pwd: " + password);
    		throw new org.identityconnectors.framework.common.exceptions.ConnectionFailedException(e);
    	}
    	
    	return newSession;
    }
	
    /**
     * Session Logout
     */
    public void sessionLogout(ClientSession session) {
        logger.info("closing Connection ID: {0}", session.getSessionId());
        try {
            this.RSAsession.logout();
            logger.info("Successful Logout");
        } catch (CommandException e) {
            logger.info("Failed to Logout of the RSA server. Error: " + e.getMessage() + " key: " +e.getMessageKey() + " cause: " + e.getCause());
        }
    }
}
