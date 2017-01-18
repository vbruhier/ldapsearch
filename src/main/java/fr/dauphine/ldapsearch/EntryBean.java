package fr.dauphine.ldapsearch;

import java.util.HashMap;
import java.util.Map;

public class EntryBean {
	
	private	String				dn			=null;
	private	Map<String,Object>	attributes	=null;
	
	public EntryBean(){
		this.attributes	=new HashMap<String,Object>();
	}
	
	/**
	 * @return the dn
	 */
	public String getDn() {
		return dn;
	}
	/**
	 * @param dn the dn to set
	 */
	public void setDn(String dn) {
		this.dn = dn;
	}
	/**
	 * @return the attributes
	 */
	public Map<String,Object> getAttributes() {
		return attributes;
	}
	/**
	 * @param attributes the attributes to set
	 */
	public void setAttributes(Map<String,Object> attributes) {
		this.attributes = attributes;
	}
	
	

}
