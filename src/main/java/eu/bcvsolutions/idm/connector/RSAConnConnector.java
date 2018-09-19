package eu.bcvsolutions.idm.connector;

import com.rsa.admin.SearchPrincipalsCommand;
import com.rsa.command.ClientSession;
import com.rsa.command.CommandException;
import com.rsa.command.CommandTargetPolicy;
import com.rsa.command.Connection;
import com.rsa.command.ConnectionFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.GuardedString.Accessor;
import org.identityconnectors.framework.api.operations.APIOperation;
import org.identityconnectors.framework.api.operations.ResolveUsernameApiOp;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptionInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.AuthenticateOp;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

//import com.rsa.authmgr.admin.ondemandmgt.data.OnDemandAuthenticatorDTO;
//import com.rsa.authmgr.admin.ondemandmgt.EnableOnDemandForPrincipalCommand;
//import com.rsa.authmgr.admin.ondemandmgt.DisableOnDemandForPrincipalCommand;

/**
 * This sample connector provides (empty) implementations for all ConnId operations, but this is not mandatory: any
 * connector can choose which operations are actually to be implemented.
 * 
 * @author Petr Hanak
 */
@ConnectorClass(configurationClass = RSAConnConfiguration.class, displayNameKey = "RSA_CONNECTOR_DISPLAY")
public class RSAConnConnector implements Connector,
        CreateOp, UpdateOp, UpdateAttributeValuesOp, DeleteOp,
        AuthenticateOp, ResolveUsernameApiOp, SchemaOp, SyncOp, TestOp, SearchOp<RSAConnFilter> {

    private static final Log LOG = Log.getLog(RSAConnConnector.class);

    private RSAConnConfiguration configuration;

	/**
	 * An instance of a Connection to the RSA Server
	 */
	private ClientSession RSAsession;
	
	private Connection conn;

    @Override
    public RSAConnConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(final Configuration configuration) {
        this.configuration = (RSAConnConfiguration) configuration;
        LOG.ok("Connector {0} successfully inited", getClass().getName());
    }

    @Override
    public void dispose() {
        // dispose of any resources the this connector uses.
    }

    @Override
    public Uid create(
            final ObjectClass objectClass,
            final Set<Attribute> createAttributes,
            final OperationOptions options) {

        return new Uid(UUID.randomUUID().toString());
    }

    @Override
    public Uid update(
            final ObjectClass objectClass,
            final Uid uid,
            final Set<Attribute> replaceAttributes,
            final OperationOptions options) {

        return uid;
    }

    @Override
    public Uid addAttributeValues(
            final ObjectClass objclass,
            final Uid uid,
            final Set<Attribute> valuesToAdd,
            final OperationOptions options) {

        return uid;
    }

    @Override
    public Uid removeAttributeValues(
            final ObjectClass objclass,
            final Uid uid,
            final Set<Attribute> valuesToRemove,
            final OperationOptions options) {

        return uid;
    }

    @Override
    public void delete(
            final ObjectClass objectClass,
            final Uid uid,
            final OperationOptions options) {
    }

    @Override
    public Uid authenticate(
            final ObjectClass objectClass,
            final String username,
            final GuardedString password,
            final OperationOptions options) {

        return new Uid(username);
    }

    @Override
    public Uid resolveUsername(
            final ObjectClass objectClass,
            final String username,
            final OperationOptions options) {

        return new Uid(username);
    }

    @Override
    public Schema schema() {
        return new Schema(
                Collections.<ObjectClassInfo>emptySet(),
                Collections.<OperationOptionInfo>emptySet(),
                Collections.<Class<? extends APIOperation>, Set<ObjectClassInfo>>emptyMap(),
                Collections.<Class<? extends APIOperation>, Set<OperationOptionInfo>>emptyMap());
    }

    @Override
    public void sync(
            final ObjectClass objectClass,
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options) {
    }

    @Override
    public SyncToken getLatestSyncToken(final ObjectClass objectClass) {
        return new SyncToken(null);
    }

    @Override
    public void test() {
    	LOG.info("Starting TEST");
//    	final GuardedString password = configuration.getPassword();
    	final String username = configuration.getUsername();
    	final String password = configuration.getStringPassword();
    	final String url = configuration.getUrl();
    	
		try {
			Connection conn = ConnectionFactory.getConnection("CommandAPIConnection");
			LOG.info("Connection factory initialized!");
			this.RSAsession = conn.connect(username, password);
			LOG.info("Username and password allright tho");
            // make all commands execute using this target automatically
			// CommandTargetPolicy.setDefaultCommandTarget(RSAsession);
//			LOG.info("Connection succeeded: {0}", this.RSAsession.getSessionId());
		} catch (CommandException e) {
			throw new ConnectionFailedException(e);
		}
		if (this.RSAsession == null) {
			throw new ConnectionFailedException("Připojení selhalo");
		}
	}

    @Override
    public FilterTranslator<RSAConnFilter> createFilterTranslator(
            final ObjectClass objectClass,
            final OperationOptions options) {

        return new AbstractFilterTranslator<RSAConnFilter>() {
        };
    }

    @Override
    public void executeQuery(
            final ObjectClass objectClass,
            final RSAConnFilter query,
            final ResultsHandler handler,
            final OperationOptions options) {

    }
}
