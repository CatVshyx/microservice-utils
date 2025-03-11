package utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

public class JwtUtils {

    public enum SIGNATURE_TYPE{
        ACCESS_KEY, GLOBAL_KEY
    }

    private final String GLOBAL_KEY;
    private final String ACCESS_KEY;
    private final long expiration;

    public JwtUtils(String globalKey, String accessKey, long exp){
        this.ACCESS_KEY = accessKey;
        this.GLOBAL_KEY = globalKey;
        this.expiration = exp;
    }

    private <T> T extractClaim(String token, Function<Claims,T> claimsResolver, SIGNATURE_TYPE signature) throws ExpiredJwtException {
        final Claims claims = extractAllClaims(token,signature);
        return  claimsResolver.apply(claims);
    }

    private Date extractExpiration(String token, SIGNATURE_TYPE signature) {
        return extractClaim(token,Claims::getExpiration, signature);
    }

    public Object  extractExtraClaims(String token, String key, SIGNATURE_TYPE signature) {
        Claims s = extractAllClaims(token,signature);
        return extractAllClaims(token,signature).get(key);
    }

    public Claims extractAllClaims(String token, SIGNATURE_TYPE signature) throws ExpiredJwtException {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey(signature == SIGNATURE_TYPE.GLOBAL_KEY ? GLOBAL_KEY: ACCESS_KEY))
                .build().parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, SIGNATURE_TYPE signature) {
        return !isTokenExpired(token,signature);
    }

    public boolean isTokenExpired(String token, SIGNATURE_TYPE signature) {
        return extractExpiration(token,signature).before(new Date());
    }

    public String generateToken(Map<String,Object> extraClaims, int exp, SIGNATURE_TYPE sign){
        return Jwts.builder().addClaims(extraClaims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60  * exp))
                .signWith(getSignKey(sign == SIGNATURE_TYPE.GLOBAL_KEY ? GLOBAL_KEY : ACCESS_KEY ), SignatureAlgorithm.HS256)
                .compact();
    }

    public int validateToken(String token, SIGNATURE_TYPE signature){
        try{
            isTokenValid(excludeToken(token),signature);
            return 200;
        }catch (SignatureException e){
            return 401;
        }catch (ExpiredJwtException e){
            return 423;
        }
    }

    private Key getSignKey(String key){
        byte[] keyBytes = key.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
    private static String excludeToken(String token){
        return token != null && token.startsWith("Bearer ")
                ? token.substring(7)
                : token;
    }

    public boolean isMicroservice(String token) throws ExpiredJwtException, SignatureException {
        if (token == null || token.length() == 0){
            return false;
        }
        return this.isTokenValid(token, SIGNATURE_TYPE.GLOBAL_KEY);
    }

}