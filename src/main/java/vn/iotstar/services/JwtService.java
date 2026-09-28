package vn.iotstar.services;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.annotation.PostConstruct;
import vn.iotstar.exception.ExpiredTokenException;
import vn.iotstar.exception.JwtAuthException;

@Service
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    private MACSigner signer;
    private MACVerifier verifier;

    @PostConstruct
    void init() {
        try {
            byte[] secret = Base64.getDecoder().decode(secretKey);
            this.signer = new MACSigner(secret);
            this.verifier = new MACVerifier(secret);
        } catch (JOSEException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid security.jwt.secret-key: " + e.getMessage(), e);
        }
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        long now = System.currentTimeMillis();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .issueTime(new Date(now))
                .expirationTime(new Date(now + jwtExpiration))
                .jwtID(UUID.randomUUID().toString());
        extraClaims.forEach(builder::claim);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build();
        SignedJWT jwt = new SignedJWT(header, builder.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }
        return jwt.serialize();
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    public String extractUsername(String token) {
        return verify(token).getSubject();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return verify(token).getSubject().equals(userDetails.getUsername());
    }

    private JWTClaimsSet verify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())) {
                throw new JwtAuthException("Unsupported JWT algorithm");
            }
            if (!jwt.verify(verifier)) {
                throw new JwtAuthException("JWT signature does not match");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp == null) {
                throw new JwtAuthException("JWT has no expiration time");
            }
            if (exp.before(new Date())) {
                throw new ExpiredTokenException("JWT expired at " + exp);
            }
            return claims;
        } catch (ParseException | JOSEException e) {
            throw new JwtAuthException("Malformed JWT: " + e.getMessage());
        }
    }
}
