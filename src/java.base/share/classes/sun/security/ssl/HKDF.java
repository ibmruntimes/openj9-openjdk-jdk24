/*
 * Copyright (c) 2018, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2025, 2025 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ssl;

/*[IF OPENJCEPLUS_SUPPORT]*/
import java.lang.IllegalAccessException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
/*[ENDIF] OPENJCEPLUS_SUPPORT */
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
/*[IF OPENJCEPLUS_SUPPORT]*/
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGenerator;
/*[ENDIF] OPENJCEPLUS_SUPPORT */
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;
/*[IF OPENJCEPLUS_SUPPORT]*/
import openj9.internal.security.RestrictedSecurity;
/*[ENDIF] OPENJCEPLUS_SUPPORT */

/**
 * An implementation of the HKDF key derivation algorithm outlined in RFC 5869,
 * specific to the needs of TLS 1.3 key derivation in JSSE.  This is not a
 * general purpose HKDF implementation and is suited only to single-key output
 * derivations.
 *
 * HKDF objects are created by specifying a message digest algorithm.  That
 * digest algorithm will be used by the HMAC function as part of the HKDF
 * derivation process.
 */
public final class HKDF {
    private final Mac hmacObj;
    private final int hmacLen;

    /*[IF OPENJCEPLUS_SUPPORT]*/
    private KeyGenerator hkdfGenerator;
    /*[ENDIF] OPENJCEPLUS_SUPPORT */

    /**
     * Create an HDKF object, specifying the underlying message digest
     * algorithm.
     *
     * @param hashAlg a standard name corresponding to a supported message
     * digest algorithm.
     *
     * @throws NoSuchAlgorithmException if that message digest algorithm does
     * not have an HMAC variant supported on any available provider.
     */
    public HKDF(String hashAlg) throws NoSuchAlgorithmException {
        Objects.requireNonNull(hashAlg,
                "Must provide underlying HKDF Digest algorithm.");
        /*[IF OPENJCEPLUS_SUPPORT]*/
        if (RestrictedSecurity.isFIPSEnabled()) {
            String hkdfAlg = "kda-hkdf-with-" + hashAlg.replace("-", "").toLowerCase();
            hkdfGenerator = KeyGenerator.getInstance(hkdfAlg);
        }
        /*[ENDIF] OPENJCEPLUS_SUPPORT */
        String hmacAlg = "Hmac" + hashAlg.replace("-", "");
        hmacObj = Mac.getInstance(hmacAlg);
        hmacLen = hmacObj.getMacLength();
    }

    /**
     * Perform the HMAC-Extract derivation.
     *
     * @param salt a salt value, implemented as a {@code SecretKey}.  A
     * {@code null} value is allowed, which will internally use an array of
     * zero bytes the same size as the underlying hash output length.
     * @param inputKey the input keying material provided as a
     * {@code SecretKey}.
     * @param keyAlg the algorithm name assigned to the resulting
     * {@code SecretKey} object.
     *
     * @return a {@code SecretKey} that is the result of the HKDF extract
     * operation.
     *
     * @throws InvalidKeyException if the {@code salt} parameter cannot be
     * used to initialize the underlying HMAC.
     */
    public SecretKey extract(SecretKey salt, SecretKey inputKey, String keyAlg)
            throws InvalidKeyException {
        if (salt == null) {
            salt = new SecretKeySpec(new byte[hmacLen], "HKDF-Salt");
        }
        /*[IF OPENJCEPLUS_SUPPORT]*/
        if (RestrictedSecurity.isFIPSEnabled()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.info("HKDF extract in FIPS mode: Using OpenJCEPlusFIPS");
            }
            try {
                Class hkdfExtractSpec = Class.forName("ibm.security.internal.spec.HKDFExtractParameterSpec", true, ClassLoader.getSystemClassLoader());
                Class[] parameterType = new Class[3];
                parameterType[0] = SecretKey.class;
                parameterType[1] = byte[].class;
                parameterType[2] = String.class;
                AlgorithmParameterSpec hkdfParams = (AlgorithmParameterSpec) hkdfExtractSpec.getDeclaredConstructor(parameterType).newInstance(inputKey, salt.getEncoded(), keyAlg);
                hkdfGenerator.init(hkdfParams);
                return hkdfGenerator.generateKey();
            } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | InvalidAlgorithmParameterException | IllegalAccessException | InvocationTargetException exc) {
                throw new SecurityException(exc);
            }
        }
        /*[ENDIF] OPENJCEPLUS_SUPPORT */
        hmacObj.init(salt);

        return new SecretKeySpec(hmacObj.doFinal(inputKey.getEncoded()),
                keyAlg);
    }

    /**
     * Perform the HMAC-Extract derivation.
     *
     * @param salt a salt value as cleartext bytes.  A {@code null} value is
     * allowed, which will internally use an array of zero bytes the same
     * size as the underlying hash output length.
     * @param inputKey the input keying material provided as a
     * {@code SecretKey}.
     * @param keyAlg the algorithm name assigned to the resulting
     * {@code SecretKey} object.
     *
     * @return a {@code SecretKey} that is the result of the HKDF extract
     * operation.
     *
     * @throws InvalidKeyException if the {@code salt} parameter cannot be
     * used to initialize the underlying HMAC.
     */
    public SecretKey extract(byte[] salt, SecretKey inputKey, String keyAlg)
            throws InvalidKeyException {
        if (salt == null) {
            salt = new byte[hmacLen];
        }
        return extract(new SecretKeySpec(salt, "HKDF-Salt"), inputKey, keyAlg);
    }

    /**
     * Perform the HKDF-Expand derivation for a single-key output.
     *
     * @param pseudoRandKey the pseudo random key (PRK).
     * @param info optional context-specific info.  A {@code null} value is
     * allowed in which case a zero-length byte array will be used.
     * @param outLen the length of the resulting {@code SecretKey}
     * @param keyAlg the algorithm name applied to the resulting
     * {@code SecretKey}
     *
     * @return the resulting key derivation as a {@code SecretKey} object
     *
     * @throws InvalidKeyException if the underlying HMAC operation cannot
     * be initialized using the provided {@code pseudoRandKey} object.
     */
    public SecretKey expand(SecretKey pseudoRandKey, byte[] info, int outLen,
            String keyAlg) throws InvalidKeyException {
        /*[IF OPENJCEPLUS_SUPPORT]*/
        if (RestrictedSecurity.isFIPSEnabled()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.info("HKDF expand in FIPS mode: Using OpenJCEPlusFIPS");
            }
            try {
                Class hkdfExpandSpec = Class.forName("ibm.security.internal.spec.HKDFExpandParameterSpec", true, ClassLoader.getSystemClassLoader());
                Class[] parameterType = new Class[4];
                parameterType[0] = SecretKey.class;
                parameterType[1] = byte[].class;
                parameterType[2] = long.class;
                parameterType[3] = String.class;
                AlgorithmParameterSpec hkdfParams = (AlgorithmParameterSpec) hkdfExpandSpec.getDeclaredConstructor(parameterType).newInstance(pseudoRandKey, info, outLen, keyAlg);
                hkdfGenerator.init(hkdfParams);
                return hkdfGenerator.generateKey();
            } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | InvalidAlgorithmParameterException | IllegalAccessException | InvocationTargetException exc) {
                throw new SecurityException(exc);
            }
        }
        /*[ENDIF] OPENJCEPLUS_SUPPORT */
        byte[] kdfOutput;

        // Calculate the number of rounds of HMAC that are needed to
        // meet the requested data.  Then set up the buffers we will need.
        Objects.requireNonNull(pseudoRandKey, "A null PRK is not allowed.");

        // Output from the expand operation must be <= 255 * hmac length
        if (outLen > 255 * hmacLen) {
            throw new IllegalArgumentException("Requested output length " +
                    "exceeds maximum length allowed for HKDF expansion");
        }
        hmacObj.init(pseudoRandKey);
        if (info == null) {
            info = new byte[0];
        }
        int rounds = (outLen + hmacLen - 1) / hmacLen;
        kdfOutput = new byte[rounds * hmacLen];
        int offset = 0;
        int tLength = 0;

        for (int i = 0; i < rounds ; i++) {

            // Calculate this round
            try {
                 // Add T(i).  This will be an empty string on the first
                 // iteration since tLength starts at zero.  After the first
                 // iteration, tLength is changed to the HMAC length for the
                 // rest of the loop.
                hmacObj.update(kdfOutput,
                        Math.max(0, offset - hmacLen), tLength);
                hmacObj.update(info);                       // Add info
                hmacObj.update((byte)(i + 1));              // Add round number
                hmacObj.doFinal(kdfOutput, offset);

                tLength = hmacLen;
                offset += hmacLen;                       // For next iteration
            } catch (ShortBufferException sbe) {
                // This really shouldn't happen given that we've
                // sized the buffers to their largest possible size up-front,
                // but just in case...
                throw new RuntimeException(sbe);
            }
        }

        return new SecretKeySpec(kdfOutput, 0, outLen, keyAlg);
    }
}

