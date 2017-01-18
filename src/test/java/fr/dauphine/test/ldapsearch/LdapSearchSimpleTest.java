package fr.dauphine.test.ldapsearch;

import static org.junit.Assert.*;

import java.io.File;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldif.LDIFReader;

import fr.dauphine.ldapsearch.LdapSearchSimple;


public class LdapSearchSimpleTest {
	private static final Logger logger = LogManager.getLogger(LdapSearchSimpleTest.class.getName());
	
	
	public	static	int LDAPTEST_PORT=8389;

	protected static InMemoryDirectoryServer ds;
	
	@Before
	public void setUp() throws Exception {
		
		// create the configuration to use for the server.
		InMemoryDirectoryServerConfig ldapconfig =new InMemoryDirectoryServerConfig("dc=dauphine,dc=fr");
		ldapconfig.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default", LDAPTEST_PORT));
		ldapconfig.addAdditionalBindCredentials("cn=root,dc=dauphine,dc=fr", "rootpwd");
		
		// create the directory server instance
	    ds = new InMemoryDirectoryServer(ldapconfig);
	    logger.info("ldap populate > import ldap-populate.ldif ...");
	    ds.importFromLDIF(true, "src/test/resources/ldap-populate.ldif" );
	    // start local memory ldap
	    logger.info("ldap start ...");
	    ds.startListening();
	}

	@After
	public void tearDown() throws Exception {
	    // stop local memory ldap
        if (ds != null) {
    	    logger.info("ldap stop !");
            ds.shutDown(true);
        }
	}

	
	@Test
    public void testInterpretationArgs() throws Exception {
		logger.info("LdapSearchSimpleTest.testInterpretationArgs()");
    	// test de l'interpretation de la requete
    	LdapSearchSimple ldapsearch = new LdapSearchSimple();
    	ldapsearch.parseCommandLine( new String[]{
			    			"-H","ldap://localhost:8389",
			    			"-F","json",
			    			"-D","uid=test,dc=dauphine,dc=fr",
			    			"-w","test",
			    			"-b","dc=dauphine,dc=fr",
			    			"-s","base",
			    			"-a","cn",
			    			"-f","(uid=*)"
    			} );
    	String	expected="ldapsearch -H ldap://localhost:8389 -D uid=test,dc=dauphine,dc=fr -w ***** -b dc=dauphine,dc=fr -s base -f (uid=*) -a cn -F json";
    	String	actual	=ldapsearch.toString();
    	logger.debug("expected :: "+expected);
    	logger.debug("actual   :: "+actual);
    	org.junit.Assert.assertEquals("ldapsearch commande :", expected, actual);
    }
	
	@Test
    public void testSearchN1() throws Exception {
		logger.info("LdapSearchSimpleTest.testSearchN1()");
    			
    	// test de l'interpretation de la requete
    	LdapSearchSimple ldapsearch = new LdapSearchSimple();
    	ldapsearch.parseCommandLine( new String[]{
			    			"-H","ldap://localhost:8389",
			    			"-D","cn=root,dc=dauphine,dc=fr",
			    			"-w","rootpwd",
			    			"-b","dc=dauphine,dc=fr",
			    			"-s","sub",
			    			"-f","(uid=*)"
    			} );
    	String	ldif	=ldapsearch.executeLdif();

    	// reponse correct
    	logger.debug("ldif result :: "+ldif);
    	org.junit.Assert.assertNotNull("resultat de requete", ldif);
    	
    	// nombre de reponse
    	if (ldif!=null){
	    	String[] ldifLines	=ldif.split("\n");
	    	String lastLine	=ldifLines[ldifLines.length-1];
	    	org.junit.Assert.assertEquals("Nombre de résultat attendu :", "# numEntries: 3", lastLine);
    	}
    }
	
	@Test
    public void testSearchN2() throws Exception {
		logger.info("LdapSearchSimpleTest.testSearchN2()");
    			
    	// test de l'interpretation de la requete
    	LdapSearchSimple ldapsearch = new LdapSearchSimple();
    	ldapsearch.parseCommandLine( new String[]{
			    			"-H","ldap://localhost:8389",
			    			"-D","cn=root,dc=dauphine,dc=fr",
			    			"-w","rootpwd",
			    			"-b","ou=groups,dc=dauphine,dc=fr",
			    			"-s","one",
			    			"-f","(owner=uid=00000003,ou=people,dc=dauphine,dc=fr)"
    			} );
    	String	ldif	=ldapsearch.executeLdif();

    	// reponse correct
    	logger.debug("ldif result :: "+ldif);
    	org.junit.Assert.assertNotNull("resultat de requete", ldif);
    	
    	// nombre de reponse
    	if (ldif!=null){
	    	String[] ldifLines	=ldif.split("\n");
	    	String lastLine	=ldifLines[ldifLines.length-1];
	    	org.junit.Assert.assertEquals("Nombre de résultat attendu :", "# numEntries: 1", lastLine);
    	}
    }
}
