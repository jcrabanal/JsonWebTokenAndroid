# JsonWebTokenAndroid
A JWT token parser in a single java file. For Android, can be easily ported to other platforms. No external dependencies, just pure java and a few Android classes.

Can do signature verification of all signing algorithms supported by the JWT standard.

    // Sample JWT and key from https://jwt.io
    JsonWebToken token = new JsonWebToken("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.gMk5N93RwgOHNH1biixLlfgMclA_FWK-VaAJC5SDc5LPjl9FajGnD9Pxa3qWiDws4BE679PmlLGiUBfQjnX_kw");
    // Pass the secret key for HMAC or use the File constructor for RSA/EC/RSAPSS with the
    // public key to verify the integrity of the token
    boolean bResult = token.verify("9sX9nGz4hEMxpXEL");
    if (!bResult) {
        throw new SecurityException("Signature does not verify");
    }
    // The full token as a JSONObject
    JSONObject json = token.toJson();
    JsonWebToken.Header header = token.getHeader();
    JsonWebToken.Claims claims = token.getClaims();
    String sIat = claims.getString("iat", "");
    int nIat = claims.getInt("iat", 0);
    ...
