import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

class AuthenticateUser {
    static String userName = "admballud_ad3@cydmodule.com";
    static String password = "Thisispassword2!";
    static String ldapURL = "ldaps://std-dc-01.cydmodule.com:636";
    static String searchBase = "OU=Users,OU=CasinoModule,OU=NetEnt Other,DC=cydmodule,DC=com";

    public static boolean authenticateUser(String userName, String password, String ldapURL) throws Exception {
        boolean isAuthenticatedUser = false;
        DirContext dirContext = getADContextForCasinoDomain(userName, password, ldapURL);
        if (dirContext != null)
        {
            isAuthenticatedUser = true;
            System.out.println("==========isAuthenticatedUser==========: " + isAuthenticatedUser);
        }
        closeADContext(dirContext);
        return isAuthenticatedUser;
    }

    public static DirContext getADContextForCasinoDomain(String userName, String password, String ldapURL) throws NamingException {
        return getSecureADContext(userName, password, ldapURL);
    }

    private static DirContext getSecureADContext(String userName, String password, String ldapURL) throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        /*if (userName == null || userName.isEmpty()) {
            userName = defaultUserName;
        }
        if (password == null || password.isEmpty()) {
            password = defaultPassword;
        }*/
        System.out.println("=======UserName=============: " + userName);
        System.out.println("=======Password=============: " + password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        env.put(Context.SECURITY_PRINCIPAL, userName);
        env.put(Context.SECURITY_CREDENTIALS, password);
        DirContext ctx = new javax.naming.directory.InitialDirContext(env);
        return ctx;
    }

    public static NamingEnumeration<SearchResult> fetchMembers() throws Exception {
        DirContext dirContext = null;
        SearchControls searchControl = new SearchControls();
        searchControl.setSearchScope(SearchControls.SUBTREE_SCOPE);
        try
        {
            //get default dirContext
            dirContext = getSecureADContext(userName, password, ldapURL);
            return searchUsers(searchControl, userName, dirContext);
        }
        finally {
            closeADContext(dirContext);
        }
    }

    private static NamingEnumeration<SearchResult> searchUsers(SearchControls searchControl, String userName, DirContext dirContext) throws Exception {
        NamingEnumeration<SearchResult> searchResult = null;
        StringBuilder searchFilter = new StringBuilder("(&");
        searchFilter.append("(objectClass=user)");
        searchFilter.append("(userPrincipalName=" + userName + ")");
        searchFilter.append(")");
        searchResult = dirContext.search(searchBase, searchFilter.toString(), searchControl);
        return searchResult;
    }

    private static void closeADContext(DirContext ctx) {
        try {
            if (ctx != null) {
                ctx.close();
            }
        } catch (NamingException nme) {
            System.out.println("Failed to close Active Directory Context: " + nme.toString());
        }
    }

    public static void main(String[] args) throws Exception {
        //Authenticate the user
        boolean isAuthenticatedUser = authenticateUser(userName, password, ldapURL);
        if (isAuthenticatedUser) {
            NamingEnumeration<SearchResult> searchResults = fetchMembers();
            if (searchResults != null) {
                while(searchResults.hasMore()) {
                    SearchResult searchResult = searchResults.next();
                    System.out.println("============Search Result============: " + searchResult.getAttributes().get("memberOf"));
                }
            }
        }
    }
}