package com.kbsriram.common.pgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import org.bouncyrattle.bcpg.ArmoredOutputStream;
import org.bouncyrattle.bcpg.HashAlgorithmTags;
import org.bouncyrattle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncyrattle.bcpg.sig.Features;
import org.bouncyrattle.bcpg.sig.KeyFlags;
import org.bouncyrattle.crypto.DataLengthException;
import org.bouncyrattle.crypto.generators.RSAKeyPairGenerator;
import org.bouncyrattle.crypto.params.RSAKeyGenerationParameters;
import org.bouncyrattle.openpgp.CStrictKeyParser;
import org.bouncyrattle.openpgp.PGPCompressedData;
import org.bouncyrattle.openpgp.PGPCompressedDataGenerator;
import org.bouncyrattle.openpgp.PGPEncryptedData;
import org.bouncyrattle.openpgp.PGPEncryptedDataGenerator;
import org.bouncyrattle.openpgp.PGPEncryptedDataList;
import org.bouncyrattle.openpgp.PGPException;
import org.bouncyrattle.openpgp.PGPKeyPair;
import org.bouncyrattle.openpgp.PGPKeyRingGenerator;
import org.bouncyrattle.openpgp.PGPLiteralData;
import org.bouncyrattle.openpgp.PGPLiteralDataGenerator;
import org.bouncyrattle.openpgp.PGPObjectFactory;
import org.bouncyrattle.openpgp.PGPOnePassSignature;
import org.bouncyrattle.openpgp.PGPOnePassSignatureList;
import org.bouncyrattle.openpgp.PGPPrivateKey;
import org.bouncyrattle.openpgp.PGPPublicKey;
import org.bouncyrattle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncyrattle.openpgp.PGPPublicKeyRing;
import org.bouncyrattle.openpgp.PGPSecretKey;
import org.bouncyrattle.openpgp.PGPSecretKeyRing;
import org.bouncyrattle.openpgp.PGPSignature;
import org.bouncyrattle.openpgp.PGPSignatureGenerator;
import org.bouncyrattle.openpgp.PGPSignatureList;
import org.bouncyrattle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncyrattle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncyrattle.openpgp.operator.PGPDigestCalculator;
import org.bouncyrattle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncyrattle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncyrattle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncyrattle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncyrattle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncyrattle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncyrattle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncyrattle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncyrattle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

public class CPGPUtils
{
    public final static class FileInfo
    {
        private FileInfo()  {}
        public String getFileName()
        { return m_name; }
        public Date getModified()
        { return m_modified; }
        public PGPPublicKeyRing getSignerKeyRing()
        { return m_signerpkr; }
        private void setSignerKeyRing(PGPPublicKeyRing pkr)
        { m_signerpkr = pkr; }
        private void setModified(Date d)
        { m_modified = d; }
        private PGPPublicKey getSignerKey()
        { return m_signerpkr.getPublicKey(); }
        private void setFileName(String s)
            throws PGPException
        {
            if (s == null) { throw new PGPException("bad name"); }
            String n = s;
            while (n.startsWith("/") || (n.startsWith("."))) {
                n = n.substring(1);
            }
            if (n.length() == 0) { throw new PGPException("bad name: "+s); }
            m_name = n;
        }
        private String m_name;
        private PGPPublicKeyRing m_signerpkr;
        private Date m_modified;
    }

    // fullkey means ensure there's also an encryption subkey.
    public final static PGPPublicKeyRing readPublicKeyRing
        (InputStream inp, boolean fullkey)
        throws IOException, PGPException, SignatureException
    { return readPublicKeyRing(inp, fullkey, null); }

    // certifying_key not-null means expect a good signature
    // on the master key's uid, signed by the certifying_key
    @SuppressWarnings("unchecked")
    public final static PGPPublicKeyRing readPublicKeyRing
        (InputStream inp, boolean fullkey, PGPPublicKey certifying_key)
        throws IOException, PGPException, SignatureException
    {
        // This uses low-level APIs to parse a strict subset of keys
        // that we're willing to accept.
        PGPPublicKeyRing pkr = CStrictKeyParser.parsePublicKeyRing
            (inp, fullkey, certifying_key != null);

        // 1) Check we have a single master key, and that it has a
        // valid self-signature.
        PGPPublicKey master = null;
        for (Iterator<PGPPublicKey> pki = pkr.getPublicKeys();
             pki.hasNext();) {
            PGPPublicKey cur = pki.next();
            if (cur.isMasterKey()) {
                if (master == null) {
                    checkMasterKey(cur, certifying_key);
                    master = cur;
                }
                else {
                    throw new PGPException("multiple master keys");
                }
            }
        }
        if (master == null) {
            throw new PGPException("no master key found");
        }

        // Every subkey must be signed by the master key.
        for (Iterator<PGPPublicKey> pki = pkr.getPublicKeys();
             pki.hasNext();) {
            PGPPublicKey cur = pki.next();
            if (!cur.isMasterKey()) {
                checkSubKey(cur, master);
            }
        }
        return pkr;
    }

    public final static boolean matchFingerprint
        (PGPPublicKey pk, String fingerprint)
    {
        if ((fingerprint == null) || (fingerprint.length() != 40)) {
            return false;
        }
        char[] target = fingerprint.toCharArray();
        byte[] actual = pk.getFingerprint();
        for (int i=0; i<20; i++) {
            int b1 = hex(target[i*2]);
            int b2 = hex(target[i*2+1]);
            int cmp = (actual[i] & 0xff);
            if ((b1 < 0) || (b2 < 0)) { return false; }
            if (cmp != (b1*16 + b2)) {
                return false;
            }
        }
        return true;
    }

    public final static String armor(byte data[])
        throws IOException
    {
        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        ArmoredOutputStream aout = new ArmoredOutputStream(baout);
        aout.setHeader("Version", "pplv1");
        aout.write(data);
        aout.close();
        return new String(baout.toByteArray(), "utf-8");
    }

    public final static String toHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<data.length; i++) {
            int v = ((int)data[i]) & 0xff;
            if (v < 0x10) {
                sb.append("0");
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    public final static String asFingerprint(PGPPublicKeyRing pkr)
    { return asFingerprint(pkr.getPublicKey()); }
    public final static String asFingerprint(PGPPublicKey pk)
    { return toHex(pk.getFingerprint()); }

    @SuppressWarnings("unchecked")
    public final static PGPSecretKeyRing updateWithNewPassword
        (PGPSecretKeyRing skr,
         char[] old_password, char[] new_password, int s2kcount)
        throws PGPException
    {
        Iterator<PGPSecretKey> okeyi = skr.getSecretKeys();
        ArrayList<PGPSecretKey> tochange = new ArrayList<PGPSecretKey>();

        while (okeyi.hasNext()) {
            PGPSecretKey osk = okeyi.next();
            if (osk.getKeyEncryptionAlgorithm() !=
                SymmetricKeyAlgorithmTags.AES_128) {
                throw new PGPException
                    ("Only read AES-128 encrypted secret keys");
            }
            tochange.add(osk);
        }
        for (PGPSecretKey osk: tochange) {
            PGPSecretKey nsk =
                PGPSecretKey.copyWithNewPassword
                (osk, new BcPBESecretKeyDecryptorBuilder
                 (new BcPGPDigestCalculatorProvider()).build(old_password),
                 new BcPBESecretKeyEncryptorBuilder
                 (PGPEncryptedData.AES_128,
                  new BcPGPDigestCalculatorProvider()
                  .get(HashAlgorithmTags.SHA256),
                  s2kcount).build(new_password));
            skr = PGPSecretKeyRing.insertSecretKey(skr, nsk);
        }
        return skr;
    }

    public final static PGPPrivateKey extractPrivateKey
        (PGPSecretKey sk, char[] password)
        throws PGPException
    {
        if (sk.getKeyEncryptionAlgorithm() !=
            SymmetricKeyAlgorithmTags.AES_128) {
            throw new PGPException
                ("Only read AES-128 encrypted secret keys");
        }

        return sk.extractPrivateKey
            (new BcPBESecretKeyDecryptorBuilder
             (new BcPGPDigestCalculatorProvider()).build(password));
    }

    @SuppressWarnings("unchecked")
    public final static PGPSecretKeyRing readSecretKeyRing(InputStream inp)
        throws PGPException, IOException, SignatureException
    {
        PGPSecretKeyRing skr = CStrictKeyParser.parseSecretKeyRing(inp);

        // Similar steps as public keys. Verify we have exactly one
        // master key, and that it has a good self-signature.
        PGPSecretKey master = null;
        for (Iterator<PGPSecretKey> ski = skr.getSecretKeys();
             ski.hasNext();) {
            PGPSecretKey cur = ski.next();
            if (cur.isMasterKey()) {
                if (master == null) {
                    checkMasterKey(cur.getPublicKey(), null);
                    master = cur;
                }
                else {
                    throw new PGPException("multiple master keys");
                }
            }
        }
        if (master == null) {
            throw new PGPException("no master key found");
        }

        // Every subkey must be signed by the master.
        for (Iterator<PGPSecretKey> ski = skr.getSecretKeys();
             ski.hasNext();) {
            PGPSecretKey cur = ski.next();
            if (!cur.isMasterKey()) {
                checkSubKey(cur.getPublicKey(), master.getPublicKey());
            }
        }
        return skr;
    }

    // only chars a-z
    public final static char[] genRandom(int len)
    {
        char[] ret = new char[len];
        SecureRandom rand = new SecureRandom();
        for (int i=0; i<len; i++) {
            ret[i] = (char) ('a' + rand.nextInt(26));
        }
        return ret;
    }

    public final static PGPKeyRingGenerator generateKeyRingGenerator
        (String uid, char[] pass, int s2kcount)
        throws PGPException
    {
        // This object generates individual key-pairs.
        RSAKeyPairGenerator  kpg = new RSAKeyPairGenerator();

        // Boilerplate RSA parameters, no need to change anything
        // except for the RSA key-size (2048). You can use whatever
        // key-size makes sense for you -- 4096, etc.
        kpg.init
            (new RSAKeyGenerationParameters
             (BigInteger.valueOf(0x10001),
              new SecureRandom(), 2048, 12));

        // First create the master (signing) key with the generator.
        PGPKeyPair rsakp_sign =
            new BcPGPKeyPair
            (PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
        // Then an encryption subkey.
        PGPKeyPair rsakp_enc =
            new BcPGPKeyPair
            (PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        // Add a self-signature on the id
        PGPSignatureSubpacketGenerator signhashgen =
            new PGPSignatureSubpacketGenerator();

        // Add signed metadata on the signature.
        // 1) Declare its purpose
        signhashgen.setKeyFlags
            (false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER);
        // 2) Set preferences for secondary crypto algorithms to use
        //    when sending messages to this key.
        signhashgen.setPreferredSymmetricAlgorithms
            (false, new int[] {
                SymmetricKeyAlgorithmTags.AES_128
            });
        signhashgen.setPreferredHashAlgorithms
            (false, new int[] {
                HashAlgorithmTags.SHA256
            });
        // 3) Request senders add additional checksums to the
        //    message (useful when verifying unsigned messages.)
        signhashgen.setFeature
            (false, Features.FEATURE_MODIFICATION_DETECTION);

        // Create a signature on the encryption subkey.
        PGPSignatureSubpacketGenerator enchashgen =
            new PGPSignatureSubpacketGenerator();
        // Add metadata to declare its purpose
        enchashgen.setKeyFlags
            (false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

        // Objects used to encrypt the secret key.
        PGPDigestCalculator sha1Calc =
            new BcPGPDigestCalculatorProvider()
            .get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc =
            new BcPGPDigestCalculatorProvider()
            .get(HashAlgorithmTags.SHA256);

        // bcpg 1.48 exposes this API that includes s2kcount. Earlier
        // versions use a default of 0x60.
        PBESecretKeyEncryptor pske =
            (new BcPBESecretKeyEncryptorBuilder
             (PGPEncryptedData.AES_128, sha256Calc, s2kcount))
            .build(pass);

        // Finally, create the keyring itself. The constructor
        // takes parameters that allow it to generate the self
        // signature.
        PGPKeyRingGenerator keyRingGen =
            new PGPKeyRingGenerator
            (PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
             /*CStrictKeyParser.PPL_MAGIC*/uid,
             sha1Calc, signhashgen.generate(), null,
             new BcPGPContentSignerBuilder
             (rsakp_sign.getPublicKey().getAlgorithm(),
              HashAlgorithmTags.SHA1),
             pske);

        // Add our encryption subkey, together with its signature.
        keyRingGen.addSubKey
            (rsakp_enc, enchashgen.generate(), null);
        return keyRingGen;
    }

    @SuppressWarnings("unchecked")
    public final static PGPSecretKey getEncryptionKey(PGPSecretKeyRing skr)
        throws PGPException
    {
        Iterator<PGPSecretKey> skit = skr.getSecretKeys();
        while (skit.hasNext()) {
            PGPSecretKey cur = skit.next();
            if (cur.getPublicKey().isEncryptionKey()) {
                return cur;
            }
        }
        throw new PGPException("No encryption key found");
    }

    @SuppressWarnings("unchecked")
    public final static PGPPublicKey getEncryptionKey(PGPPublicKeyRing pkr)
        throws PGPException
    {
        Iterator<PGPPublicKey> pkit = pkr.getPublicKeys();
        while (pkit.hasNext()) {
            PGPPublicKey cur = pkit.next();
            if (cur.isEncryptionKey()) {
                return cur;
            }
        }
        throw new PGPException("No encryption key found");
    }

    @SuppressWarnings("unchecked")
    public final static PGPSecretKey getSigningKey(PGPSecretKeyRing skr)
        throws PGPException
    {
        Iterator<PGPSecretKey> skit = skr.getSecretKeys();
        while (skit.hasNext()) {
            PGPSecretKey cur = skit.next();
            if (cur.isSigningKey()) {
                return cur;
            }
        }
        throw new PGPException("No signing key found");
    }

    // Simply check that this is a reasonably valid encrypted file.
    public final static void checkEncrypted(InputStream in)
        throws PGPException, IOException
    {
        // Expect a list of session keys, followed by a single
        // encrypted packet.
        PGPObjectFactory  pgpF = new PGPObjectFactory(in);
        Object o = pgpF.nextObject();
        if (!(o instanceof PGPEncryptedDataList)) {
            throw new PGPException("Missing encrypted session keys.");
        }
        PGPEncryptedDataList edl = (PGPEncryptedDataList) o;

        // Ensure that we only accept anonymous public key packets
        int count = edl.size();
        if (count == 0) {
            throw new PGPException("Missing encrypted session keys.");
        }

        PGPPublicKeyEncryptedData any = null;

        for (int i=0; i<count; i++) {
            o = edl.get(i);
            if (!(o instanceof PGPPublicKeyEncryptedData)) {
                throw new PGPException("Only accept public key encrypted data");
            }
            any = ((PGPPublicKeyEncryptedData)o);
            if (any.getKeyID() != 0l) {
                throw new PGPException("Only accept anonymous encrypted data");
            }
            if (!any.isIntegrityProtected()) {
                throw new PGPException("Only accept integrity protected data");
            }
        }
    }

    public final static FileInfo extractEncryptedData
        (InputStream in, List<PGPPublicKeyRing> signers, PGPPrivateKey enckey,
         OutputStream out)
        throws PGPException, IOException, SignatureException
    {
        // Expect a list of session keys, followed by a single
        // encrypted packet.
        PGPObjectFactory  pgpF = new PGPObjectFactory(in);
        Object o = pgpF.nextObject();
        if (!(o instanceof PGPEncryptedDataList)) {
            throw new PGPException("Missing encrypted session keys.");
        }
        PGPEncryptedDataList edl = (PGPEncryptedDataList) o;

        // Ensure that we only accept anonymous public key packets,
        // and pull out our data stream from one of the session keys.
        PublicKeyDataDecryptorFactory df =
            new BcPublicKeyDataDecryptorFactory(enckey);
        int count = edl.size();
        InputStream dataStream = null;
        PGPPublicKeyEncryptedData edata = null;
        for (int i=0; i<count; i++) {
            o = edl.get(i);
            if (!(o instanceof PGPPublicKeyEncryptedData)) {
                throw new PGPException("Only accept public key encrypted data");
            }
            PGPPublicKeyEncryptedData cur = ((PGPPublicKeyEncryptedData)o);
            if (cur.getKeyID() != 0l) {
                throw new PGPException("Only accept anonymous encrypted data");
            }
            // If we haven't seen it already, check if we can get the
            // stream.
            if (dataStream == null) {
                try {
                    dataStream = cur.getDataStream(df);
                    edata = cur;
                }
                catch (Throwable ign) {
                    // Not ours -- keep going.
                    dataStream = null;
                    edata = null;
                }
            }
        }
        if (dataStream == null) {
            throw new PGPException("Cannot decrypt data");
        }
        // Confirm that we're not seeing unencrypted traffic.
        if (edata.getSymmetricAlgorithm(df) ==
            SymmetricKeyAlgorithmTags.NULL) {
            throw new PGPException("Won't accept unencrypted data");
        }
        if (!edata.isIntegrityProtected()) {
            throw new PGPException
                ("Only accept integrity protected data");
        }
        FileInfo ret = extractSignedData(dataStream, signers, out);
        if (!edata.verify()) {
            throw new PGPException("Integrity check failed");
        }
        return ret;
    }

    public final static FileInfo extractSignedData
        (InputStream in, List<PGPPublicKeyRing> signers, OutputStream out)
        throws PGPException, IOException, SignatureException
    {
        FileInfo ret = new FileInfo();
        // Use convenience methods from PGPObjectFactory
        PGPObjectFactory objectStream = new PGPObjectFactory(in);

        // allow a single compressed packet if present.
        Object o = objectStream.nextObject();
        if (o instanceof PGPCompressedData) {
            // use a nested objectStream instead.
            objectStream =
                new PGPObjectFactory(((PGPCompressedData) o).getDataStream());
            o = objectStream.nextObject();
        }

        // We expect to see a list of signature headers, then a
        // literal packet, and another list of signatures.

        // 1. One-pass headers.
        if (!(o instanceof PGPOnePassSignatureList)) {
            throw new PGPException("Missing signature header: "+o);
        }
        // Pull out a signature that we're willing to use, and update
        // info with the public key that we use.
        PGPOnePassSignature mysignature =
            signatureFor((PGPOnePassSignatureList) o, signers, ret);

        // 2. Literal packet.
        o = objectStream.nextObject();
        if (!(o instanceof PGPLiteralData)) {
            throw new PGPException("Missing literal data");
        }
        PGPLiteralData ldata = (PGPLiteralData) o;
        ret.setFileName(ldata.getFileName());
        ret.setModified(ldata.getModificationTime());

        // 2.5 Copy the data to the outputstream, and also
        // update the signature so we may verify it.
        mysignature.init(s_provider, ret.getSignerKey());
        InputStream ldin = ldata.getInputStream();
        byte buf[] = new byte[8192];
        int nread;
        while ((nread = ldin.read(buf)) > 0) {
            out.write(buf, 0, nread);
            mysignature.update(buf, 0, nread);
        }
        out.close();

        // 3. Signature trailer.
        o = objectStream.nextObject();
        if (!(o instanceof PGPSignatureList)) {
            throw new PGPException("Missing signature");
        }
        if (!mysignature.verify
            (signatureFor((PGPSignatureList)o, ret.getSignerKey()))) {
            throw new PGPException("bad signature, reject data");
        }
        if (objectStream.nextObject() != null) {
            throw new PGPException("Unexpected trailing data, reject");
        }
        return ret;
    }

    private final static PGPSignature signatureFor
        (PGPSignatureList siglist, PGPPublicKey pk)
        throws PGPException
    {
        int count = siglist.size();
        for (int i=0; i<count; i++) {
            PGPSignature cur = siglist.get(i);
            // Approximate match -- "close enough" for typical
            // needs.
            if (cur.getKeyID() == pk.getKeyID()) {
                return cur;
            }
        }
        throw new PGPException("No usable signatures.");
    }

    // Select one among the provided candidate signatures, also
    // updating fileinfo with the signer ring.
    private final static PGPOnePassSignature signatureFor
        (PGPOnePassSignatureList siglist,
         List<PGPPublicKeyRing> signers, FileInfo info)
        throws PGPException
    {
        int count = siglist.size();
        for (int i=0; i<count; i++) {
            PGPOnePassSignature cur = siglist.get(i);
            // Approximate match -- "close enough" for typical
            // needs.
            for (PGPPublicKeyRing signer: signers) {
                if (cur.getKeyID() == signer.getPublicKey().getKeyID()) {
                    info.setSignerKeyRing(signer);
                    return cur;
                }
            }
        }
        throw new PGPException("No usable signatures.");
    }

    public final static void writeEncryptedSignedData
        (File src, OutputStream out,
         List<PGPPublicKey> enckeys, PGPPrivateKey signkey,
         String name, Date timestamp, boolean compress)
        throws IOException, PGPException, SignatureException
    {
        PGPEncryptedDataGenerator encGen =
            new PGPEncryptedDataGenerator
            (new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_128)
             .setWithIntegrityPacket(true));
        for (PGPPublicKey enckey: enckeys) {
            encGen.addMethod
                (new CAnonymousPublicKeyKeyEncryptionMethodGenerator(enckey));
        }
        OutputStream encOut = encGen.open(out, new byte[1<<16]);
        writeSignedData(src, encOut, signkey, name, timestamp, compress);
        encGen.close();
    }

    public final static void writeSignedData
        (File src, OutputStream out, PGPPrivateKey signkey,
         String name, Date timestamp, boolean compress)
        throws PGPException, IOException, SignatureException
    {
        OutputStream comOut;
        PGPCompressedDataGenerator comGen;
        if (compress) {
            // Wrap everything in a compressed packet.
            comGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            comOut = comGen.open(out);
        }
        else {
            comGen = null;
            comOut = out;
        }

        // Dump 3 packets.
        // one-pass signature header
        // literal data
        // signature
        PGPSignatureGenerator sGen =
            new PGPSignatureGenerator
            (new BcPGPContentSignerBuilder
             (signkey.getPublicKeyPacket().getAlgorithm(),
              HashAlgorithmTags.SHA256));
        sGen.init(PGPSignature.BINARY_DOCUMENT, signkey);

        // 1. Header packet
        sGen.generateOnePassVersion(false).encode(comOut);

        // 2. Literal data packet.
        writeLiteralPacket(src, comOut, sGen, name, timestamp);

        // 3. Write signature
        sGen.generate().encode(comOut);

        if (comGen != null) {
            // Close compressor to flush out last bits.
            comGen.close();
        }
    }

    // Add an "i-trust-this-user-id" signature to the master key,
    // signed by the provided private key. (Used to approve other
    // people's public keys once verified.)
    //
    public final static PGPPublicKeyRing certifyPublicKeyRing
        (PGPPublicKeyRing certifypkr, PGPPrivateKey sign_key)
        throws PGPException, SignatureException
    {
        PGPPublicKey orig_master = certifypkr.getPublicKey();
        if (!orig_master.isMasterKey()) {
            throw new IllegalArgumentException("Unexpected - not master");
        }

        String uid = getExactlyOneUserId(orig_master);

        // Create a signature for it.
        PGPSignatureGenerator sgen =
            new PGPSignatureGenerator
            (new BcPGPContentSignerBuilder
             (sign_key.getPublicKeyPacket().getAlgorithm(),
              HashAlgorithmTags.SHA256));
        sgen.init(PGPSignature.DEFAULT_CERTIFICATION, sign_key);

        PGPPublicKey certified_master = PGPPublicKey.addCertification
            (orig_master, uid, sgen.generateCertification(uid, orig_master));

        return PGPPublicKeyRing.insertPublicKey(certifypkr, certified_master);
    }

    @SuppressWarnings("unchecked")
    private final static String getExactlyOneUserId(PGPPublicKey pk)
        throws PGPException
    {
        Iterator<String> uids = pk.getUserIDs();
        if ((uids == null) || (!uids.hasNext())) {
            throw new PGPException("No userids available");
        }
        String ret = uids.next();
        if (uids.hasNext()) {
            throw new PGPException("Multiple userids found");
        }
        return ret;
    }

    private final static int hex(char cur)
    {
        if ((cur >= '0') && (cur <= '9')) {
            return (cur - '0');
        }
        if ((cur >= 'a') & (cur <= 'f')) {
            return (cur - 'a') + 10;
        }
        if ((cur >= 'A') && (cur <= 'F')) {
            return (cur - 'A') + 10;
        }
        return -1;
    }

    private final static void writeLiteralPacket
        (File src, OutputStream out, PGPSignatureGenerator sGen,
         String name, Date timestamp)
        throws IOException, SignatureException
    {
        PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();
        FileInputStream fin = null;
        try {
            fin = new FileInputStream(src);
            OutputStream ldOut = ldGen.open
                (out, PGPLiteralData.BINARY, name, fin.available(), timestamp);
            byte[] buf = new byte[4192];
            int nread;
            while ((nread = fin.read(buf)) > 0) {
                ldOut.write(buf, 0, nread);
                sGen.update(buf, 0, nread);
            }
            ldGen.close();
        }
        finally {
            if (fin != null) {
                try { fin.close(); } catch (Throwable ign) {}
            }
        }
    }

    @SuppressWarnings("unchecked")
    private final static void checkSubKey
        (PGPPublicKey subkey, PGPPublicKey master)
        throws PGPException,SignatureException
    {
        Iterator<PGPSignature> sigs = subkey.getSignatures();
        boolean ok = false;
        if (sigs == null) {
            throw new PGPException("No signatures available");
        }

        // See if any of the subkey-certifying signatures from
        // the subkey work.
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            if ((sig.getKeyID() != master.getKeyID()) ||
                (sig.getSignatureType() != PGPSignature.SUBKEY_BINDING)) {
                continue;
            }
            sig.init(s_provider, master);
            ok = sig.verifyCertification(master, subkey);
            if (ok) {
                break;
            }
        }
        if (!ok) {
            throw new PGPException("Subkey not signed by master key");
        }
    }

    @SuppressWarnings("unchecked")
    private final static void checkMasterKey
        (PGPPublicKey master, PGPPublicKey certifying_key)
        throws PGPException,SignatureException
    {
        // 1) The key should not have expired.
        long vs = master.getValidSeconds();
        if (vs != 0) {
            long expire = master.getCreationTime().getTime()+(vs*1000);
            long now = System.currentTimeMillis();
            if (expire < now) {
                throw new PGPException
                    ("Sorry, this certificate expired on "+
                     new Date(expire));
            }
        }

        // 2) Collect all the user-ids, and ensure that we
        // have a good self-signature and if needed, a
        // certifying signature for each one.
        Map<String,Boolean> checked_uids = new HashMap<String,Boolean>();
        Map<String,Boolean> certified_uids;
        if (certifying_key != null) {
            certified_uids = new HashMap<String,Boolean>();
        }
        else {
            certified_uids = null;
        }
        for (Iterator<String> uids = master.getUserIDs(); uids.hasNext();) {
            String uid = uids.next();
            checked_uids.put(uid, false);
            if (certified_uids != null) {
                certified_uids.put(uid, false);
            }
        }
        if (checked_uids.isEmpty()) {
            throw new PGPException("No uids found for master key.");
        }
        Iterator<PGPSignature> sigs = master.getSignatures();
        if (sigs == null) {
            throw new PGPException("No signatures available on master key.");
        }
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            // Ignore anything that's not a self-certification.
            if ((sig.getSignatureType() < PGPSignature.DEFAULT_CERTIFICATION) ||
                (sig.getSignatureType() > PGPSignature.POSITIVE_CERTIFICATION)){
                continue;
            }

            // Proceed only if the signature is signed with either the
            // master key, or the certifying_key (if non-null)
            if (sig.getKeyID() != master.getKeyID()) {
                if ((certifying_key == null) ||
                    (sig.getKeyID() != certifying_key.getKeyID())) {
                    continue;
                }
            }
            // See if it can certify any unverified uid
            if (sig.getKeyID() == master.getKeyID()) {
                updateVerification(checked_uids, sig, master, master);
            }
            // Hits this only if certifying_key != null. If I screw up,
            // NPE -- is also fine.
            else if (sig.getKeyID() == certifying_key.getKeyID()) {
                updateVerification(certified_uids, sig, certifying_key, master);
            }
            else {
                throw new IllegalStateException("Should not be here!");
            }

        }
        // 3) Make sure every uid in the key has a good signature.
        for (String uid: checked_uids.keySet()) {
            if (!checked_uids.get(uid)) {
                throw new PGPException("No signature found for "+uid);
            }
        }
        if (certified_uids != null) {
            for (String uid: certified_uids.keySet()) {
                if (!certified_uids.get(uid)) {
                    throw new PGPException
                        ("No certification found for "+uid);
                }
            }
        }
    }

    private final static void updateVerification
        (Map<String,Boolean> checked, PGPSignature sig,
         PGPPublicKey signer, PGPPublicKey tobecertified)
        throws PGPException, SignatureException
    {
        for (String uid: checked.keySet()) {
            if (checked.get(uid)) {
                continue;
            }
            sig.init(s_provider, signer);
            if (sig.verifyCertification(uid, tobecertified)) {
                checked.put(uid, true);
                break;
            }
        }
    }

    private final static BcPGPContentVerifierBuilderProvider s_provider =
        new BcPGPContentVerifierBuilderProvider();
    private static final BigInteger ONE = BigInteger.valueOf(1);
}
