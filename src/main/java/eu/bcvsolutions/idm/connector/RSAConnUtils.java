package eu.bcvsolutions.idm.connector;

import javax.naming.NamingException;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;

import com.rsa.admin.AddAdminRoleCommand;
import com.rsa.admin.GetPrincipalAdminRolesCommand;
import com.rsa.admin.SearchPrincipalsCommand;
import com.rsa.admin.data.AdminRoleDTO;
import com.rsa.admin.data.PrincipalDTO;
import com.rsa.admin.data.SecurityDomainDTO;
import com.rsa.authmgr.admin.ondemandmgt.DisableOnDemandForPrincipalCommand;
import com.rsa.authmgr.admin.ondemandmgt.EnableOnDemandForPrincipalCommand;
import com.rsa.authmgr.admin.ondemandmgt.data.OnDemandAuthenticatorDTO;
import com.rsa.authmgr.common.ondemandmgt.PinIndicator;
import com.rsa.authmgr.common.ondemandmgt.TransmissionMechanism;
import com.rsa.command.ClientSession;
import com.rsa.command.CommandException;
import com.rsa.command.CommandTargetPolicy;
import com.rsa.command.exception.DataNotFoundException;
import com.rsa.command.exception.DuplicateDataException;
import com.rsa.command.exception.InsufficientPrivilegeException;
import com.rsa.command.exception.InvalidArgumentException;
import com.rsa.common.SystemException;
import com.rsa.common.search.Filter;

/**
 * Connector utils
 * 
 * 
 * @author Petr Hanak
 */
public class RSAConnUtils {
	
	/**
     * Place holder for the Connection created in the init method.
     */
    private RSAConnConnection connection;

	private RSAConnConfiguration configuration;
	
    /**
     * An instance of a Connection to the RSA Server
     */
    private ClientSession RSAsession;
	
	private static final Log logger = Log.getLog(RSAConnConnection.class);
	
    public RSAConnUtils(final RSAConnConnection connection) {
        this.connection = connection;
    }
    
    /**
     * Returns the plain password of a GuardedString
     * 
     * @param password the GuardedString storing the encrypted pwd to decrypt and return.
     * @return A String representing the clear text password.
     */
    public static String getPlainPassword(GuardedString password) {
        if (password == null) {
            return null;
        }
        final StringBuffer buf = new StringBuffer();
        password.access(new GuardedString.Accessor() {
            public void access(char[] clearChars) {
                buf.append(clearChars);
            }
        });
        return buf.toString();
    }
    
    /**
     * Lookup a user by login UID.
     *
     * @param userId the user login UID
     * @return the user record.
     * @throws Exception
     */
    public static PrincipalDTO lookupUser(String userId, RSAConnConnection connection) throws Exception {
    	logger.info("searching for login.. " + userId);
        SearchPrincipalsCommand searchPrincipals = new SearchPrincipalsCommand();

        // create a filter with the login UID equal condition
        searchPrincipals.setFilter(Filter.equal(PrincipalDTO.LOGINUID, userId));
        searchPrincipals.setSystemFilter(Filter.empty());
        searchPrincipals.setLimit(1);
        searchPrincipals.setIdentitySourceGuid(connection.getIdSource().getGuid());
        searchPrincipals.setSecurityDomainGuid(connection.getDomain().getGuid());
        searchPrincipals.execute(connection.getRSASession());

        if (searchPrincipals.getPrincipals().length < 1) {
            throw new UnknownUidException("Unable to find user " + userId + ".");
        } else {
        	logger.info("Found User: " + searchPrincipals.getPrincipals()[0].getFirstName() + " " + searchPrincipals.getPrincipals()[0].getLastName());
        }
        return searchPrincipals.getPrincipals()[0];
    }
    
    public static PrincipalDTO createPrincipalUser(RSAConnConnection connection, RSAConnConfiguration configuration) {
    	String[] identitySourceScope = {configuration.getIdentitySource()};
    	AdminRoleDTO adminRole = new AdminRoleDTO();
//        adminRole.setSuperAdminRole(true);
        adminRole.setIdentitySourceScope(identitySourceScope);
        adminRole.setSecurityDomainName(configuration.getSecurityDomain());
        
//        AddAdminRoleCommand addCmd = new AddAdminRoleCommand();
//        addCmd.setAdminRole(adminRole);
//        addCmd.execute(cmdTarget);
        
        PrincipalDTO principal = new PrincipalDTO();
        principal.setUserID("testovaciAdmin");
        principal.setPassword("admintest");

        principal.setEnabled(true);
        principal.setCanBeImpersonated(false);
        principal.setTrustToImpersonate(false);

        principal.setSecurityDomainGuid(connection.getDomain().getGuid());
        principal.setIdentitySourceGuid(connection.getIdSource().getGuid());
        // require user to change password at next login
        principal.setPasswordExpired(false);
        principal.setAdminRole(true);
		return principal;
    }
    
    public void enableOnDemandAuthentication(PrincipalDTO user, String pin, RSAConnConfiguration configuration) {
    	this.configuration = (RSAConnConfiguration) configuration;
    	try {
			this.connection = new RSAConnConnection(this.configuration);
			this.RSAsession = connection.newSession();
		} catch (NamingException e2) {
			e2.printStackTrace();
		}
//			From the logs provided, It seems that Administrative role did not have identity source scope specified,
//			please Utilize AdminRoleDTO.setIdentitySourceScope when creating a role via the AddAdminRoleCommand.
    	
		try {
			OnDemandAuthenticatorDTO authenticator = new OnDemandAuthenticatorDTO();
			logger.info("enableOnDemandAuthentication SMTP");
			authenticator.setPrincipalGuid(user.getGuid());
			authenticator.setPinType(PinIndicator.SET_PERM_PIN);
			authenticator.setPin(pin);
			authenticator.setDeliveryMethod(TransmissionMechanism.SMTP);
//			authenticator.setSMSDestinationAddress("+420608947331@sms1.koop.cz");
			authenticator.setSMTPAddress("+420608947331@sms1.koop.cz");
			logger.info("enableOnDemandAuthentication DefaultCommandTarget: " + CommandTargetPolicy.getDefaultCommandTarget());
			
			EnableOnDemandForPrincipalCommand enableOnDemandForPrincipal = new EnableOnDemandForPrincipalCommand();
			enableOnDemandForPrincipal.setOnDemandAuthenticatorDTO(authenticator);
			enableOnDemandForPrincipal.execute();
			connection.sessionLogout(this.RSAsession);
			logger.info("ODA ENABLED!");
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
    
    public void disableOnDemandAuthentication(PrincipalDTO user) {
		try {
			ClientSession ses = connection.newCmdClientSession();
			DisableOnDemandForPrincipalCommand cmd = new DisableOnDemandForPrincipalCommand(user.getGuid());
			cmd.execute();
			connection.sessionLogout(ses);
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
    
    public static AdminRoleDTO[] getPrincipalAdminRoles(PrincipalDTO user, RSAConnConnection connection) {
    	GetPrincipalAdminRolesCommand getAdminRoles = new GetPrincipalAdminRolesCommand();
    	getAdminRoles.setGuid(user.getGuid());
        
		try {
			getAdminRoles.execute(connection.getRSASession());
		} catch (DataNotFoundException e) {
			e.printStackTrace();
		} catch (InvalidArgumentException e) {
			e.printStackTrace();
		} catch (CommandException e) {
			e.printStackTrace();
		} catch (SystemException e) {
			e.printStackTrace();
		}
    	AdminRoleDTO[] adminRoles = getAdminRoles.getAdminRoles();
    		for(AdminRoleDTO adminRole : adminRoles) {
    			logger.info("Admin role: " + adminRole);
    		}
    	return adminRoles;
    }
}
