package fr.dauphine.ldapsearch;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.nimbusds.common.ldap.JSONResultFormatter;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

public class LdapSearchSimple {
	private static final Logger logger = LogManager.getLogger(LdapSearchSimple.class.getName());

	private String serverurl = "localhost";
	private String userdn = "cn=root,dc=localhost";
	private String userpw = "password";
	private String basedn = "dc=localhost";
	private String scope = "one";
	private String filter = "(objectClass=*)";
	private String attributes = null;
	private String outputFormat = "ldif";

	public LdapSearchSimple() {
	}

	public static String parseArgs(String[] args) {
		String fullargs = "";
		for (int i = 0; i < args.length; i++) {
			fullargs += args[i] + " ";
		}
		if (fullargs.length() > 0)
			fullargs = fullargs.substring(0, fullargs.length() - 1);
		return fullargs;
	}

	public String doSearchLdif(String basedn, String scope, String filter) {
		return this.doSearchLdif(basedn, scope, filter);
	}

	/**
	 * @return the serverurl
	 */
	public String getServerUrl() {
		return serverurl;
	}

	/**
	 * @param serverurl
	 *            the serverurl to set
	 */
	public void setServerUrl(String serverurl) {
		this.serverurl = serverurl;
	}

	/**
	 * @return the userdn
	 */
	public String getUserDN() {
		return userdn;
	}

	/**
	 * @param userdn
	 *            the userdn to set
	 */
	public void setUserDN(String userdn) {
		this.userdn = userdn;
	}

	/**
	 * @return the userpw
	 */
	public String getUserPassword() {
		return userpw;
	}

	/**
	 * @param userpw
	 *            the userpw to set
	 */
	public void setUserPassword(String userpw) {
		this.userpw = userpw;
	}

	/**
	 * @return the basedn
	 */
	public String getBasedn() {
		return basedn;
	}

	/**
	 * @param basedn
	 *            the basedn to set
	 */
	public void setBasedn(String basedn) {
		this.basedn = basedn;
	}

	/**
	 * @return the scope
	 */
	public String getScope() {
		return scope;
	}

	/**
	 * @param scope
	 *            the scope to set
	 */
	public void setScope(String scope) {
		this.scope = scope;
	}

	/**
	 * @return the filter
	 */
	public String getFilter() {
		return filter;
	}

	/**
	 * @param filter
	 *            the filter to set
	 */
	public void setFilter(String filter) {
		this.filter = filter;
	}

	/**
	 * @return the attributes
	 */
	public String getAttributes() {
		return attributes;
	}

	/**
	 * @param attributes
	 *            the attributes to set
	 */
	public void setAttributes(String attributes) {
		this.attributes = attributes;
	}

	/**
	 * communication ssl
	 * 
	 * @return
	 */
	public boolean isSsl() {
		return this.getServerUrl() != null && this.getServerUrl().toLowerCase().startsWith("ldaps://");
	}

	public void parseCommandLine(String[] args) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-H") && i + 1 < args.length)
				this.setServerUrl(args[i + 1]);
			if (args[i].equals("-D") && i + 1 < args.length)
				this.setUserDN(args[i + 1]);
			if (args[i].equals("-w") && i + 1 < args.length)
				this.setUserPassword(args[i + 1]);
			if (args[i].equals("-b") && i + 1 < args.length)
				this.setBasedn(args[i + 1]);
			if (args[i].equals("-s") && i + 1 < args.length)
				this.setScope(args[i + 1]);
			if (args[i].equals("-f") && i + 1 < args.length)
				this.setFilter(args[i + 1]);
			if (args[i].equals("-a") && i + 1 < args.length)
				this.setAttributes(args[i + 1]);
			if (args[i].equals("-F") && i + 1 < args.length)
				this.setOutputFormat( args[i + 1] );
		}
	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("ldapsearch");
		sb.append(" -H ");
		sb.append(this.getServerUrl());
		sb.append(" -D ");
		sb.append(this.getUserDN());
		sb.append(" -w ");
		sb.append("*****");
		sb.append(" -b ");
		sb.append(this.getBasedn());
		sb.append(" -s ");
		sb.append(this.getScope());
		sb.append(" -f ");
		sb.append(this.getFilter());
		if (this.getAttributes() == null || this.getAttributes().split(",").length == 0) {
			sb.append(" -a ALL");
		} else {
			sb.append(" -a ");
			sb.append(this.getAttributes());
		}
		sb.append(" -F ");
		sb.append(this.getOutputFormat());
		return sb.toString();
	}

	/**
	 * make new LdapConnexion
	 * 
	 * @return LdapConnexion
	 * @throws LDAPException
	 * @throws GeneralSecurityException
	 * @throws SupannLibException
	 */
	public LDAPConnection getNewConnection() throws LDAPException, GeneralSecurityException {
		LDAPConnection ldapconnection = null;
		try {
			logger.debug("creation ldap-connexion");
			// create a new connection pool with <nb> connections established
			// and authenticated to the same server
			if (this.isSsl()) {
				SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
				ldapconnection = new LDAPConnection(sslUtil.createSSLSocketFactory());
			} else {
				ldapconnection = new LDAPConnection();
			}
			// parse hostname
			String withoutprotocole = this.getServerUrl().toLowerCase();
			withoutprotocole = withoutprotocole.replace("ldap://", "");
			withoutprotocole = withoutprotocole.replace("ldaps://", "");
			String hostname = withoutprotocole;
			if (hostname.contains(":"))
				hostname = hostname.split(":")[0];
			int port = 389;
			if (this.isSsl())
				port = 636;
			if (withoutprotocole.contains(":")) {
				String sport = withoutprotocole.toLowerCase();
				sport = sport.replace("/", "");
				port = Integer.parseInt(sport.split(":")[1]);
			}
			logger.debug("ldapconnection.connect(" + hostname + ", " + port + ");");
			ldapconnection.connect(hostname, port);
			if (this.getUserDN() != null)
				ldapconnection.bind(this.getUserDN(), this.getUserPassword());
			ldapconnection.getConnectionOptions().setUseKeepAlive(true);

			logger.debug("create ldap connexion -> ok");
		} catch (java.lang.NumberFormatException ex) {
			logger.error("LdapConfig -> format exception");
			logger.error("LdapConfig -> " + this.toString());
			logger.error("------------------------------------------");
			logger.error("LDAP URL : wrong syntax -> '-H " + this.getServerUrl() + "'");
			logger.error("------------------------------------------");
			ldapconnection = null;
			throw ex;
		} catch (LDAPException ex) {
			logger.error("LdapConfig -> can not etablish LDAP connection");
			logger.error("LdapConfig -> " + this.toString());
			logger.error("------------------------------------------");
			logger.error("LDAPException");
			logger.error("   error code          : " + ex.getResultCode());
			logger.error("   error text          : " + ex.getExceptionMessage());
			logger.error("   localized message   : " + ex.getLocalizedMessage());
			logger.error("   message             : " + ex.getMessage());
			logger.error("   diagnostic message  : " + ex.getDiagnosticMessage());
			logger.error("------------------------------------------");
			ldapconnection = null;
			throw ex;
		} catch (GeneralSecurityException ex) {
			logger.error("LdapConfig -> can not etablish LDAP connection");
			logger.error("LdapConfig -> " + this.toString());
			logger.error("------------------------------------------");
			logger.error("GeneralSecurityException");
			logger.error("   ssl layer can not be etablished");
			logger.error("------------------------------------------");
			ldapconnection = null;
			throw ex;
		}
		return ldapconnection;
	}

	public String	toLdif(SearchResult searchResult){
		StringBuffer	sb=new StringBuffer();
		// affichage ldif
		// Write all of the matching entries to LDIF.
		int	countEntries	=0;
		if ( searchResult!=null ) {
			if ( searchResult.getSearchEntries()!=null ){
				for (Iterator<SearchResultEntry> itSearchEntry = searchResult.getSearchEntries().iterator(); itSearchEntry.hasNext();) {
					SearchResultEntry entry = itSearchEntry.next();
					sb.append(entry.toLDIFString());
					sb.append('\n');
					countEntries++;
				}
			}
			sb.append('\n');
			sb.append("# numEntries: "+countEntries+"\n");
		}
		return sb.toString();
	}
	
	private	String toJson(SearchResult searchResult){
		ArrayList< Map<String,Object> > jsonEntries	=new ArrayList< Map<String,Object> >();
		if ( searchResult!=null ){
			if ( searchResult.getSearchEntries()!=null ){
				for (Iterator<SearchResultEntry> itSearchEntry = searchResult.getSearchEntries().iterator(); itSearchEntry.hasNext();) {
					SearchResultEntry	entry	=itSearchEntry.next();
					Set<String> attrnames	=new HashSet<String>();
					for(Iterator<Attribute> itAttr=entry.getAttributes().iterator();itAttr.hasNext();){
						Attribute	attr	=itAttr.next();
						attrnames.add( attr.getName() );
					}
					Map<String,Object> mapEntryJson=JSONResultFormatter.formatEntry(entry, attrnames, false);
					//Gson gson = new Gson(); 
					//json += gson.toJson(mapJson) +"\n";
					jsonEntries.add( mapEntryJson );
				}
			}
		}
		Gson gson = new Gson(); 
		return gson.toJson( jsonEntries );
	}
	
	public String	toJSON(SearchResult searchResult){
		StringBuffer	sb=new StringBuffer();
		// affichage ldif
		// Write all of the matching entries to LDIF.
		int	countEntries	=0;
		if ( searchResult!=null ) {
			if ( searchResult.getSearchEntries()!=null ){
				for (Iterator<SearchResultEntry> itSearchEntry = searchResult.getSearchEntries().iterator(); itSearchEntry.hasNext();) {
					SearchResultEntry entry = itSearchEntry.next();
					sb.append(entry.toLDIFString());
					sb.append('\n');
					countEntries++;
				}
			}
			sb.append('\n');
			sb.append("# numEntries: "+countEntries+"\n");
		}
		return sb.toString();
	}
	
	
	public String executeLdif() throws LDAPException, GeneralSecurityException {
		String	result	=null;
		logger.debug("LdapTools.executeLdif()");
		SearchResult searchResult = null;
		SearchScope scope = SearchScope.ONE;
		try {
			LDAPConnection ldapcx = this.getNewConnection();
			if (this.getScope().toLowerCase().equals("base"))
				scope = SearchScope.BASE;
			if (this.getScope().toLowerCase().equals("one"))
				scope = SearchScope.ONE;
			if (this.getScope().toLowerCase().equals("sub"))
				scope = SearchScope.SUB;

			String[] attributeNames = null;
			if (this.getAttributes()!= null && this.getAttributes().split(",").length>0 )
				attributeNames = this.getAttributes().split(",");

			// execution de la recherche
			if (attributeNames == null) {
				// lancement recherche
				searchResult = ldapcx.search(
										this.getBasedn(), // base de recherche
										scope, // scope de recherche
										this.getFilter() // filtre de recherche
									);
			} else {
				searchResult = ldapcx.search(
										this.getBasedn(), // base de recherche
										scope, // scope de recherche
										this.getFilter(), // filtre de recherche
										attributeNames // liste des attributs a retourner
									);
			}

			String	outputFormat	=(this.getOutputFormat()==null)?"ldif":this.getOutputFormat().toLowerCase();
			if ( outputFormat.equals("json") )	result =this.toJson(searchResult);
			if ( outputFormat.equals("ldif") )	result =this.toLdif(searchResult);
			if ( result==null )
				result =this.toLdif(searchResult);
			
			ldapcx.close();

		} catch (LDAPException ex) {
			logger.error("--- Erreur LDAP ---");
			logger.error("  error message  : " + ex.getExceptionMessage());
			logger.error("  result code    : " + ex.getResultCode());
			logger.error("  message        : " + ex.getMessage());
			logger.error("  local message  : " + ex.getLocalizedMessage());
			logger.error("  cause          : " + ex.getCause());
			logger.error("Erreur ldapsearch : ", ex);
			result="ldap_error ("+ex.getResultCode()+"): "+ex.getExceptionMessage();
			throw ex;
		}
		return result;
	}
	
	
	private	Map<String,Object>	entryAttributeSelection(Entry personEntry,Set<String> lAttrsBinairies,Set<String> lAttrsSelection){
		Map<String,Object>	result			=new HashMap<String,Object>();
		Map<String,Object>	allAttributes	=JSONResultFormatter.formatEntry(
													personEntry,
													lAttrsBinairies,
													false,
													true
												);
		for(Iterator<String> itKeys=allAttributes.keySet().iterator();itKeys.hasNext();){
			String	key	=itKeys.next();
			if ( lAttrsSelection.contains(key) )
				result.put(key, allAttributes.get(key) );
		}
		return result;		
	}
	
	public void executeSearchLdif() throws LDAPException, GeneralSecurityException {
		
		System.out.println(this.executeLdif());
	}

	public static void main(String[] args) throws LDAPException, GeneralSecurityException {
		LdapSearchSimple ldapsearch = new LdapSearchSimple();
		ldapsearch.parseCommandLine(args);
		logger.debug("command line >> " + ldapsearch);

		ldapsearch.executeSearchLdif();
	}

	/**
	 * @return the outputFormat
	 */
	public String getOutputFormat() {
		return outputFormat;
	}

	/**
	 * @param outputFormat the outputFormat to set
	 */
	public void setOutputFormat(String outputFormat) {
		this.outputFormat = outputFormat;
	}

}