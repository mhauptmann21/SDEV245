/*
Original Code:

if (inputPassword.equals(user.getPassword())) { 
    // Login success
}

Vulnerability:

Plaintext Storage: user.getPassword() appears to return the stored password (likely plaintext)
Insecure comparison: If storing hashed passwords and doing equals() on strings can leak timing 
info; comparisons must be constant-time when checking secrets

Fix:

Use PBKDF2/bcrypt + constant-time comparison
Use a password library or MessageDigest.isEqual() for 
constant-time comparison.
*/

import org.mindrot.jbcrypt.BCrypt;

public boolean verifyPassword(String inputPassword, String storedHash) {
    return BCrypt.checkpw(inputPassword, storedHash); // library does safe comparison
}
