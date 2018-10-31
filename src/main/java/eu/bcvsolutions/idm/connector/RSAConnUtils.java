package eu.bcvsolutions.idm.connector;

import javax.naming.NamingException;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;

import com.rsa.admin.AddAdminRoleCommand;
import com.rsa.admin.SearchPrincipalsCommand;
import com.rsa.admin.data.AdminRoleDTO;
import com.rsa.admin.data.PrincipalDTO;
import com.rsa.admin.data.SecurityDomainDTO;
import com.rsa.authmgr.admin.ondemandmgt.DisableOnDemandForPrincipalCommand;
import com.rsa.authmgr.admin.ondemandmgt.EnableOnDemandForPrincipalCommand;
import com.rsa.authmgr.admin.ondemandmgt.data.OnDemandAuthenticatorDTO;
import com.rsa.authmgr.common.ondemandmgt.PinIndicator;
import com.rsa.command.ClientSession;
import com.rsa.command.CommandException;
import com.rsa.command.CommandTargetPolicy;
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
        SearchPrincipalsCommand cmd = new SearchPrincipalsCommand();

        // create a filter with the login UID equal condition
        cmd.setFilter(Filter.equal(PrincipalDTO.LOGINUID, userId));
        cmd.setSystemFilter(Filter.empty());
        cmd.setLimit(1);
        cmd.setIdentitySourceGuid(connection.getIdSource().getGuid());
        cmd.setSecurityDomainGuid(connection.getDomain().getGuid());
//        cmd.setGroupGuid(null);
//        cmd.setOnlyRegistered(true);
//        cmd.setSearchSubDomains(true);
//        cmd.setAttributeMask(new String[]{"ALL_INTRINSIC_ATTRIBUTES", "CORE_ATTRIBUTES", "SYSTEM_ATTRIBUTES", "ALL_EXTENDED_ATTRIBUTES"}); //"ALL_ATTRIBUTES"
        ClientSession ses = connection.newSession();
        cmd.execute(ses);
        connection.sessionLogout(ses);

        if (cmd.getPrincipals().length < 1) {
            throw new UnknownUidException("Unable to find user " + userId + ".");
        } else {
        	logger.info("Found User: " + cmd.getPrincipals()[0].getFirstName() + " " + cmd.getPrincipals()[0].getLastName());
        }

        return cmd.getPrincipals()[0];
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
	        // Set super admin permission to default command target        
//	        String[] identitySourceScope = {"DC=testkoop,DC=int"};
//	        String[] securityDomainScope = {connection.getDomain().SEARCH_SCOPE_ONE_LEVEL};
//	        AdminRoleDTO adminRole = new AdminRoleDTO();
//	        adminRole.setSuperAdminRole(true);
//	        adminRole.setName("ConnectorAdminRole");
//	        adminRole.setSecurityDomainGuid(connection.getDomain().getGuid());
//	        adminRole.setDomainScope(securityDomainScope);
//	        adminRole.setIdentitySourceScope(identitySourceScope);
//	        logger.info("ADMIN ROLE PERMISSIONS: " + adminRole.getPermissions());;
//	        
//	        AddAdminRoleCommand addAdminRoleCommand = new AddAdminRoleCommand();
//	        addAdminRoleCommand.setAdminRole(adminRole);
//	        try {
//				addAdminRoleCommand.execute(this.RSAsession);
//			} catch (DuplicateDataException e1) {
//				e1.printStackTrace();
//			} catch (InsufficientPrivilegeException e1) {
//				e1.printStackTrace();
//			} catch (InvalidArgumentException e1) {
//				e1.printStackTrace();
//			} catch (CommandException e1) {
//				e1.printStackTrace();
//			} catch (SystemException e1) {
//				e1.printStackTrace();
//			}
	        
			OnDemandAuthenticatorDTO authenticator = new OnDemandAuthenticatorDTO();
			logger.info("enableOnDemandAuthentication SMTP");
			authenticator.setPrincipalGuid(user.getGuid());
			authenticator.setPinType(PinIndicator.SET_PERM_PIN);
			authenticator.setPin(pin);
//			authenticator.setSMSDestinationAddress("+420608947331@sms1.koop.cz");
			authenticator.setSMTPAddress("+420608947331@sms1.koop.cz");
			logger.info("enableOnDemandAuthentication DefaultCommandTarget: " + CommandTargetPolicy.getDefaultCommandTarget());
			
			EnableOnDemandForPrincipalCommand cmd = new EnableOnDemandForPrincipalCommand();
			cmd.setOnDemandAuthenticatorDTO(authenticator);
			cmd.execute();
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
}
