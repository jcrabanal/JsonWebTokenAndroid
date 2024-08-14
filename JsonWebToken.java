package com.reaper;

import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;

import androidx.annotation.CheckResult;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JsonWebToken {

    @NonNull
    private final String sHeader;
    @NonNull
    private final String sPayload;
    @NonNull
    private final Header header;
    @NonNull
    private final Claims claims;
    @NonNull
    private final String sSignature;

    public JsonWebToken(@NonNull String sToken) {
        if (TextUtils.isEmpty(sToken)) {
            throw new IllegalArgumentException("Token parameter cannot be empty");
        }
        String[] sAllTokenSections = sToken.split("\\.");
        if (sAllTokenSections.length < 3) {
            throw new IllegalArgumentException("Token is malformed");
        }
        // Los JWT se componen de tres secciones, header, claims (donde está la miga) y firma
        this.sHeader = sAllTokenSections[0];
        this.sPayload = sAllTokenSections[1];
        this.header = new Header(parseJwtSection(sHeader));
        this.claims = new Claims(parseJwtSection(sPayload));
        this.sSignature = sAllTokenSections[2];
    }

    @CheckResult
    @NonNull
    private JSONObject parseJwtSection(@NonNull String sSection) {
        byte[] value = Base64.decode(sSection, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING);
        try {
            //noinspection CharsetObjectCanBeUsed
            String sJson = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT ? new String(value, StandardCharsets.UTF_8) : new String(value, "UTF-8");
            return new JSONObject(sJson);
        } catch (UnsupportedEncodingException | JSONException ex) {
            throw throwUnchecked(ex);
        }
    }

    @SuppressWarnings("unused")
    @CheckResult
    @NonNull
    public Header getHeader() {
        return header;
    }

    @SuppressWarnings("unused")
    @CheckResult
    @NonNull
    public Claims getClaims() {
        return claims;
    }

    @SuppressWarnings("unused")
    @CheckResult
    @NonNull
    public String getSignature() {
        return sSignature;
    }

    public boolean verify(@NonNull File fPublicKey) {
        String sKeyData = readFile(fPublicKey);
        byte[] bufferKey = getPublicKeyBytes(sKeyData);
        return verify(bufferKey);
    }

    public boolean verify(@NonNull String sKey) {
        byte[] bufferKey = getUtf8Bytes(sKey);
        return verify(bufferKey);
    }

    public boolean verify(@NonNull byte[] bufferKey) {
        //noinspection ConstantValue
        if (bufferKey == null) {
            throw new IllegalArgumentException("Empty key argument");
        }
        String sAlgorithm = header.getAlgorithm();
        switch (sAlgorithm) {
            case "HS256":
                return doHmacWithShaCheck(bufferKey, 256);
            case "HS384":
                return doHmacWithShaCheck(bufferKey, 384);
            case "HS512":
                return doHmacWithShaCheck(bufferKey, 512);
            case "RS256":
                return doRsaWithShaCheck(bufferKey, 256, false);
            case "RS384":
                return doRsaWithShaCheck(bufferKey, 384, false);
            case "RS512":
                return doRsaWithShaCheck(bufferKey, 512, false);
            case "ES256":
                return doEcWithShaCheck(bufferKey, 256);
            case "ES384":
                return doEcWithShaCheck(bufferKey, 384);
            case "ES512":
                return doEcWithShaCheck(bufferKey, 512);
            case "PS256":
                return doRsaWithShaCheck(bufferKey, 256, true);
            case "PS384":
                return doRsaWithShaCheck(bufferKey, 384, true);
            case "PS512":
                return doRsaWithShaCheck(bufferKey, 512, true);
            case "none":
                return true;
            default:
                throw new UnsupportedOperationException("Not implemented: " + sAlgorithm);
        }
    }

    private boolean doHmacWithShaCheck(@NonNull byte[] bufferKey, int nKeySize) {
        try {
            String sAlgorithm = "HmacSHA" + nKeySize;
            SecretKeySpec keySpec = new SecretKeySpec(bufferKey, sAlgorithm);
            Mac mac = Mac.getInstance(sAlgorithm);
            mac.init(keySpec);
            byte[] buffer = getUtf8Bytes(sHeader + "." + sPayload);
            byte[] bufferSignature = mac.doFinal(buffer);
            String sSignatureEncoded = Base64.encodeToString(bufferSignature, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING);
            return TextUtils.equals(sSignatureEncoded, sSignature);
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            throw throwUnchecked(ex);
        }
    }

    private boolean doRsaWithShaCheck(@NonNull byte[] bufferPublicKey,
                                      int nKeySize,
                                      boolean bUseMgf1) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(bufferPublicKey));
            String sAlgorithm = bUseMgf1 ? "SHA" + nKeySize + "withRSAandMGF1" : "SHA" + nKeySize + "withRSA";
            byte[] bufferSignature = Base64.decode(sSignature, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING);
            Signature signature = Signature.getInstance(sAlgorithm);
            signature.initVerify(publicKey);
            signature.update(getUtf8Bytes(sHeader + "." + sPayload));
            return signature.verify(bufferSignature);
        } catch (NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException
                 | InvalidKeySpecException ex) {
            throw throwUnchecked(ex);
        }
    }

    private boolean doEcWithShaCheck(@NonNull byte[] bufferPublicKey, int nKeySize) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(bufferPublicKey));
            byte[] bufferSignature = Base64.decode(sSignature, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING);
            bufferSignature = toDer(bufferSignature, nKeySize);
            Signature signature = Signature.getInstance("SHA" + nKeySize + "withECDSA");
            signature.initVerify(publicKey);
            signature.update(getUtf8Bytes(sHeader + "." + sPayload));
            return signature.verify(bufferSignature);
        } catch (NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException
                 | InvalidKeySpecException ex) {
            throw throwUnchecked(ex);
        }
    }

    @CheckResult
    @NonNull
    public JSONObject toJson() {
        try {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("header", header.getJson());
            jsonObject.put("claims", claims.getJson());
            jsonObject.put("signature", sSignature);
            return jsonObject;
        } catch (JSONException ex) {
            throw throwUnchecked(ex);
        }
    }

    private static int countPadding(byte[] buffer, int nFromIndex, int nToIndex) {
        int nPadding = 0;
        while (nFromIndex + nPadding < nToIndex && buffer[nFromIndex + nPadding] == 0) {
            nPadding++;
        }
        return (buffer[nFromIndex + nPadding] & 0xff) > 0x7f ? nPadding - 1 : nPadding;
    }

    @NonNull
    private static byte[] toDer(byte[] bufferJoseSignature, int nKeySize) {
        int nEcNumberSize;
        switch (nKeySize) {
            case 256:
                nEcNumberSize = 32;
                break;
            case 384:
                nEcNumberSize = 48;
                break;
            case 512:
                nEcNumberSize = 66;
                break;
            default:
                throw new IllegalArgumentException("Invalid EC key size: " + nKeySize);
        }
        int nRPadding = countPadding(bufferJoseSignature, 0, nEcNumberSize);
        int nSPadding = countPadding(bufferJoseSignature, nEcNumberSize, bufferJoseSignature.length);
        int nRLength = nEcNumberSize - nRPadding;
        int nSLength = nEcNumberSize - nSPadding;
        int nLength = 2 + nRLength + 2 + nSLength;
        final byte[] derSignature;
        int offset;
        if (nLength > 0x7f) {
            derSignature = new byte[3 + nLength];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + nLength];
            offset = 1;
        }
        derSignature[0] = (byte) 0x30;
        derSignature[offset++] = (byte) (nLength & 0xff);
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) nRLength;
        if (nRPadding < 0) {
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(bufferJoseSignature, 0, derSignature, offset, nEcNumberSize);
            offset += nEcNumberSize;
        } else {
            int copyLength = Math.min(nEcNumberSize, nRLength);
            System.arraycopy(bufferJoseSignature, nRPadding, derSignature, offset, copyLength);
            offset += copyLength;
        }
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) nSLength;
        if (nSPadding < 0) {
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(bufferJoseSignature, nEcNumberSize, derSignature, offset, nEcNumberSize);
        } else {
            System.arraycopy(bufferJoseSignature, nEcNumberSize + nSPadding, derSignature, offset, Math.min(nEcNumberSize, nSLength));
        }
        return derSignature;
    }

    private static byte[] getPublicKeyBytes(@NonNull CharSequence csKeyData) {
        String sKeyData = csKeyData.toString();
        sKeyData = sKeyData.replace("-----BEGIN PUBLIC KEY-----", "");
        sKeyData = sKeyData.replace("-----END PUBLIC KEY-----", "");
        sKeyData = sKeyData.replace("-----BEGIN RSA PUBLIC KEY-----", "");
        sKeyData = sKeyData.replace("-----END RSA PUBLIC KEY-----", "");
        sKeyData = sKeyData.replace("-----BEGIN ENCRYPTED PUBLIC KEY-----", "");
        sKeyData = sKeyData.replace("-----END ENCRYPTED PUBLIC KEY-----", "");
        sKeyData = sKeyData.replaceAll("\n", "");
        return Base64.decode(sKeyData, Base64.NO_WRAP | Base64.NO_PADDING);
    }

    @CheckResult
    @NonNull
    private static String readFile(@NonNull File file) {
        FileInputStream fis = null;
        InputStreamReader isr = null;
        BufferedReader br = null;
        try {
            fis = new FileInputStream(file);
            //noinspection CharsetObjectCanBeUsed
            isr = new InputStreamReader(fis, "UTF-8");
            br = new BufferedReader(isr);
            String sLine = br.readLine();
            StringBuilder sb = new StringBuilder();
            while (sLine != null) {
                sb.append(sLine);
                sb.append('\n');
                sLine = br.readLine();
            }
            return sb.toString();
        } catch (IOException ex) {
            throw throwUnchecked(ex);
        } finally {
            closeSafely(br, isr, fis);
        }
    }

    private static void closeSafely(Closeable... closeables) {
        if (closeables == null) {
            return;
        }
        if (closeables.length == 0) {
            return;
        }
        for (int i = 0; i < closeables.length; i++) {
            try {
                if (closeables[i] == null) {
                    continue;
                }
                closeables[i].close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            closeables[i] = null;
        }
    }

    @CheckResult
    @NonNull
    static RuntimeException throwUnchecked(@NonNull final Throwable t) {
        if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
        }
        throwUncheckedInternal(t);
        throw new AssertionError("Dead code!");
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void throwUncheckedInternal(@NonNull final Throwable t) throws T {
        throw (T) t;
    }

    @NonNull
    private static byte[] getUtf8Bytes(@NonNull String str) {
        if (TextUtils.isEmpty(str)) {
            return new byte[0];
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            return str.getBytes(StandardCharsets.UTF_8);
        }
        try {
            //noinspection CharsetObjectCanBeUsed
            return str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw throwUnchecked(ex);
        }
    }

    public static class Header {

        @NonNull
        private final JSONObject jsonHeader;
        private final String sAlgorithm;
        private final String sType;

        public Header(@NonNull JSONObject jsonHeader) {
            this.jsonHeader = jsonHeader;
            this.sAlgorithm = jsonHeader.optString("alg", "");
            this.sType = jsonHeader.optString("type", "");
        }

        @SuppressWarnings("unused")
        @CheckResult
        @NonNull
        public String getAlgorithm() {
            return sAlgorithm;
        }

        @SuppressWarnings("unused")
        @CheckResult
        @NonNull
        public String getType() {
            return sType;
        }

        @CheckResult
        @NonNull
        public JSONObject getJson() {
            return jsonHeader;
        }
    }

    public static class Claims {

        @NonNull
        private final JSONObject jsonClaims;
        @NonNull
        private final String sSub;
        @NonNull
        private final String sName;
        @NonNull
        private final String sIat;

        public Claims(@NonNull JSONObject jsonClaims) {
            this.jsonClaims = jsonClaims;
            this.sSub = jsonClaims.optString("sub", "");
            this.sName = jsonClaims.optString("name", "");
            this.sIat = jsonClaims.optString("iat", "");
        }

        @SuppressWarnings("unused")
        @CheckResult
        @NonNull
        public String getSub() {
            return sSub;
        }

        @SuppressWarnings("unused")
        @CheckResult
        @NonNull
        public String getName() {
            return sName;
        }

        @SuppressWarnings("unused")
        @CheckResult
        @NonNull
        public String getIat() {
            return sIat;
        }

        @SuppressWarnings("unused")
        @CheckResult
        public <Z> Z get(@NonNull String sKey, @Nullable Z defaultValue) {
            Object value = jsonClaims.opt(sKey);
            if (value == JSONObject.NULL || value == null) {
                return defaultValue;
            }
            //noinspection unchecked
            return (Z) value;
        }

        @SuppressWarnings("unused")
        @CheckResult
        public String getString(@NonNull String sKey, @Nullable String sDefault) {
            String sValue = jsonClaims.optString(sKey, sDefault);
            if (sValue == JSONObject.NULL) {
                return sDefault;
            }
            return sValue;
        }

        @SuppressWarnings("unused")
        @CheckResult
        public int getInt(@NonNull String sKey, int nDefault) {
            return jsonClaims.optInt(sKey, nDefault);
        }

        @SuppressWarnings("unused")
        @CheckResult
        public double getDouble(@NonNull String sKey, double nDefault) {
            return jsonClaims.optDouble(sKey, nDefault);
        }

        @SuppressWarnings("unused")
        @CheckResult
        public boolean getBoolean(@NonNull String sKey, boolean bDefault) {
            return jsonClaims.optBoolean(sKey, bDefault);
        }

        @CheckResult
        @NonNull
        public JSONObject getJson() {
            return jsonClaims;
        }
    }
}