// Deliberately vulnerable file for security pipeline validation.
// Should trigger CodeQL CWE-89 (SQL Injection) at HIGH severity.
package security.test;

import java.sql.*;

public class SqlInjectionDemo {
    public ResultSet lookup(Connection conn, String userInput) throws SQLException {
        // Tainted concatenation -> SQL injection sink
        String sql = "SELECT * FROM users WHERE id = " + userInput;
        return conn.createStatement().executeQuery(sql);
    }

    public void weakHash(String password) throws Exception {
        // Should trigger CodeQL CWE-327 (Weak Cryptographic Algorithm)
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
    }
}
