package eu.bcvsolutions.idm.connector;

import com.rsa.command.CommandTargetPolicy;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
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

import com.rsa.authmgr.common.AdminResource;
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
        this.connection = new RSAConnConnection(this.configuration);
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
    	
        return new Uid(UUID.randomUUID().toString());
    }

    @Override
    public Uid update(
            final ObjectClass objectClass,
            final Uid uid,
            final Set<Attribute> replaceAttributes,
            final OperationOptions options) {
    	logger.info("UPDATE METHOD");
    	
//    	1) Najít uživatele
//    	final RSAConnUtils utils = new RSAConnUtils(this.getConnection());
    	
//    	2) Povolit On-demand authentication a nastavit PIN
    	logger.info("Uid name", uid.getName());
    	logger.info("Uid value", uid.getUidValue());
    	try {
    		
//			utils.enableOnDemandAuthentication(utils.lookUpUser(uid.getName()));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
//    	attributes.add(AttributeInfoBuilder.build(OnDemandAuthenticatorDTO));
    	
    	attributes.add(AttributeInfoBuilder.build("PIN"));
    	attributes.add(AttributeInfoBuilder.build("ENABLED"));
    	
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.EMAIL));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.FIRST_NAME));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.LAST_NAME));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.MIDDLE_NAME));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.CERTDN));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.DESCRIPTION));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.ADMINISTRATOR_FLAG));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.EXPIRATION_DATE));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.IMPERSONATABLE_FLAG));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.IMPERSONATOR_FLAG));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.LAST_UPDATED_BY));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.LAST_UPDATED_ON));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.LOCKOUT_FLAG));
    	attributes.add(AttributeInfoBuilder.build(PrincipalDTO.START_DATE));
    	attributes.add(AttributeInfoBuilder.build(AdminResource.DEFAULTSHELL));
    	
    	// Build Schema
        schemaBuilder.defineObjectClass(ObjectClass.ACCOUNT_NAME, attributes);
        
        return schemaBuilder.build();
        
//    	return new Schema(
//                Collections.<ObjectClassInfo>emptySet(),
//                Collections.<OperationOptionInfo>emptySet(),
//                Collections.<Class<? extends APIOperation>, Set<ObjectClassInfo>>emptyMap(),
//                Collections.<Class<? extends APIOperation>, Set<OperationOptionInfo>>emptyMap());
        
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
//        this.connection.test();
        String defCommandTgt = null;
        defCommandTgt = CommandTargetPolicy.getDefaultCommandTarget().toString();
        logger.info("Using default command target for this thread: {0}",defCommandTgt);
        
//        enableOnDemandAuthentication("vkotynek");
        
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
				user = utils.lookUpUser(query.getValue().toString());
			} catch (Exception e) {
				throw new ConnectorException(e);
			}
    		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
    		user.getAttributes();
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
