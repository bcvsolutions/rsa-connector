package eu.bcvsolutions.idm.connector;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;

import com.rsa.admin.SearchPrincipalsCommand;
import com.rsa.admin.data.PrincipalDTO;
import com.rsa.authmgr.admin.ondemandmgt.DisableOnDemandForPrincipalCommand;
import com.rsa.authmgr.admin.ondemandmgt.EnableOnDemandForPrincipalCommand;
import com.rsa.authmgr.admin.ondemandmgt.data.OnDemandAuthenticatorDTO;
import com.rsa.authmgr.common.ondemandmgt.PinIndicator;
import com.rsa.command.ClientSession;
import com.rsa.common.search.Filter;

/**
 * Connector utils
 * 
 * 
 * @author Petr Hanak
 */
public class RSAConnUtils {
	
	private final RSAConnConnection connection;
	
	private static final Log logger = Log.getLog(RSAConnConnection.class);
	
    public RSAConnUtils(final RSAConnConnection connection) {
        this.connection = connection;
    }
    
    /**
     * Lookup a user by login UID.
     *
     * @param userId the user login UID
     * @return the user record.
     * @throws Exception
     */
    public PrincipalDTO lookUpUser(String userId) throws Exception {
    	logger.info("searching for lodin.. " + userId);
        SearchPrincipalsCommand cmd = new SearchPrincipalsCommand();

        // create a filter with the login UID equal condition
        cmd.setFilter(Filter.equal(PrincipalDTO.LOGINUID, userId));
//        cmd.setFilter(Filter.startsWith(PrincipalDTO.LOGINUID, "vkot"));
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
    
    public void enableOnDemandAuthentication(String userId) {
    	ClientSession ses = connection.newCmdClientSession();
			try {
				PrincipalDTO user = lookUpUser(userId);
				OnDemandAuthenticatorDTO authenticator = new OnDemandAuthenticatorDTO();
				authenticator.setPrincipalGuid(user.getGuid());
				authenticator.setPinType(PinIndicator.SET_PERM_PIN);
				authenticator.setPin("1234");
				authenticator.setOnDemandEnabledOn(null);
				EnableOnDemandForPrincipalCommand cmd = new EnableOnDemandForPrincipalCommand(authenticator); 
				cmd.execute();
				logger.info("ODA ENABLED!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		connection.sessionLogout(ses);
    }
    
    public void disableOnDemandAuthentication(String userId) {
		try {
			PrincipalDTO user = lookUpUser(userId);
			DisableOnDemandForPrincipalCommand cmd = new DisableOnDemandForPrincipalCommand(userId);
			cmd.execute();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
}
