package eu.bcvsolutions.idm.connector;

import com.rsa.command.CommandTargetPolicy;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import javax.naming.NamingException;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.operations.ResolveUsernameApiOp;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
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

import com.rsa.admin.data.AttributeDTO;
import com.rsa.admin.data.PrincipalDTO;

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

    /**
     * Setup logging for the {@link RSAConnConnector}.
     */
    private static final Log logger = Log.getLog(RSAConnConnector.class);

    private RSAConnConfiguration configuration;
	
	/**
     * Place holder for the Connection created in the init method.
     */
    private RSAConnConnection connection;

    /**
     * Gets the Connection context for this connector.
     *
     * @return The current RSA Connection
     */
    public RSAConnConnection getConnection() {
        return connection;
    }

    @Override
    public RSAConnConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(final Configuration configuration) {
        this.configuration = (RSAConnConfiguration) configuration;
        try {
			this.connection = new RSAConnConnection(this.configuration);
		} catch (NamingException e) {
			e.printStackTrace();
		}
        logger.ok("Connector {0} successfully inited", getClass().getName());
    }

    @Override
    public void dispose() {
        if (connection != null) {
            connection.dispose();
            connection = null;
        }
        configuration = null;
    }

    @Override
    public Uid create(
            final ObjectClass objectClass,
            final Set<Attribute> createAttributes,
            final OperationOptions options) {
    	
    	logger.info("CREATE METHOD");
    	// vyhodit chybu
    	
        return new Uid(UUID.randomUUID().toString());
    }

    @Override
    public Uid update(
            final ObjectClass objectClass,
            final Uid uid,
            final Set<Attribute> replaceAttributes,
            final OperationOptions options) {
    	logger.info("UPDATE METHOD");
    	logger.info("Uid value: " + uid.getUidValue());
    	String pin = "";
    	boolean enabled = false;
    	boolean hasPhone = false;
    	for(Attribute attr : replaceAttributes) {
    		logger.info("rplc attr: " + attr.getName() + " " + attr.getValue().get(0).toString());
    		if (attr.getName().equals(RSAConnConfiguration.PIN)) {
    			pin = attr.getValue().get(0).toString();
    		} else if (attr.getName().equals(RSAConnConfiguration.ENABLED)) {
    			enabled = attr.getValue() == null || attr.getValue().isEmpty() || Boolean.parseBoolean(attr.getValue().get(0).toString());
    		} else if (attr.getName().equals(RSAConnConfiguration.PHONE)) {
    			hasPhone = !(attr.getValue() == null || attr.getValue().get(0).toString().length() < 9);
    			logger.info("HAS PHONE: " + hasPhone);
    		}
    	}
    	
    	final RSAConnUtils utils = new RSAConnUtils(this.getConnection());
    	if (enabled && hasPhone) {
    		try {
    			// Find user DTO, allow On-demand authentication and set new PIN
    			 utils.enableOnDemandAuthentication(RSAConnUtils.lookupUser(uid.getUidValue(), connection), pin, this.configuration);
    		} catch (Exception e) {
    			e.printStackTrace();
    		}
    	} else {
    		try {
    			// Disable On-demand authentication
				utils.disableOnDemandAuthentication(RSAConnUtils.lookupUser(uid.getUidValue(), connection));
			} catch (Exception e) {
				e.printStackTrace();
			}
    	}
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
		
    	final RSAConnUtils utils = new RSAConnUtils(this.getConnection());
    	try {
			// Disable On-demand authentication
			utils.disableOnDemandAuthentication(RSAConnUtils.lookupUser(uid.getUidValue(), connection));
		} catch (Exception e) {
			e.printStackTrace();
		}
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
    	logger.info("Building Schema configuration...");
    	// Create Schema
    	SchemaBuilder schemaBuilder = new SchemaBuilder(getClass());
    	Set<AttributeInfo> attributes = new HashSet<AttributeInfo>();
    	
    	//USER Objects
    	logger.info("USER attributes...");
    	// Mandatory Attribute NAME
    	AttributeInfoBuilder nmeBuilder = new AttributeInfoBuilder();
    	nmeBuilder.setCreateable(true);
    	nmeBuilder.setUpdateable(true);
    	nmeBuilder.setName(Name.NAME);
    	attributes.add(nmeBuilder.build());
    	// Mandatory Attribute UID
    	AttributeInfoBuilder uidBuilder = new AttributeInfoBuilder();
    	uidBuilder.setCreateable(true);
    	uidBuilder.setUpdateable(true);
    	uidBuilder.setName(Uid.NAME);
    	attributes.add(uidBuilder.build());
    	
    	//Add all RSA User Principal attributes
    	attributes.add(AttributeInfoBuilder.build("PIN"));
    	attributes.add(AttributeInfoBuilder.build("ENABLED", Boolean.class));
    	attributes.add(AttributeInfoBuilder.build("PHONE"));
    	
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.EMAIL));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.FIRST_NAME));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.LAST_NAME));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.MIDDLE_NAME));
    	
    	// Build Schema
        schemaBuilder.defineObjectClass(ObjectClass.ACCOUNT_NAME, attributes);
        return schemaBuilder.build();
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
        logger.info("Performing Connector Test");
        this.connection.test();
        String defCommandTgt = null;
        defCommandTgt = CommandTargetPolicy.getDefaultCommandTarget().toString();
        logger.info("Using default command target for this thread: {0}",defCommandTgt);
        
        /*try {
            this.lookupSecurityDomain(this.configuration.getSecurityDomain());
        } catch (Exception ex) {
            logger.error("Connection Test Failed: {0}", ex.getMessage());
            throw new RuntimeException("Connection Test Failed", ex);
        }*/
	}

    @Override
    public FilterTranslator<RSAConnFilter> createFilterTranslator(
            final ObjectClass objectClass,
            final OperationOptions options) {

        return new AbstractFilterTranslator<RSAConnFilter>() {

			@Override
			protected RSAConnFilter createEqualsExpression(EqualsFilter filter, boolean not) {
				logger.info("CREATE EQUALS EXPRESSION");
				RSAConnFilter result = new RSAConnFilter();
				result.setAttr(filter.getName());
				// TODO 
				if (filter.getAttribute().getValue().size() > 0) {
					result.setValue(filter.getAttribute().getValue().get(0));
				}
				return result;
			}
        };
    }

    @Override
    public void executeQuery(
            final ObjectClass objectClass,
            final RSAConnFilter query,
            final ResultsHandler handler,
            final OperationOptions options) {
    	logger.info("EXECUTE QUERY");
    	RSAConnUtils utils = new RSAConnUtils(connection);
    	if(query.getAttr().equals(Uid.NAME)) {
    		PrincipalDTO user;
			try {
				user = RSAConnUtils.lookupUser(query.getValue().toString(), connection);
			} catch (Exception e) {
				throw new ConnectorException(e);
			}
    		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
    		logger.info("user attr size: ", user.getAttributes().length);
    		for (AttributeDTO attr : user.getAttributes()) {
    			builder.addAttribute(convertAttribute(attr));
    			logger.info("adding attribute: " + attr.getName());
    		}
    		builder.setUid(user.getUserID());
    		builder.setName(user.getUserID());
    		handler.handle(builder.build());
    	}
    }

	private Attribute convertAttribute(AttributeDTO attr) {
		AttributeBuilder builder = new AttributeBuilder();
		
		builder.setName(attr.getName());
		builder.addValue(attr.getValues());
		return builder.build();
	}
}
