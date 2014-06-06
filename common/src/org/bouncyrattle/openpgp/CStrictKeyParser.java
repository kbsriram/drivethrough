package org.bouncyrattle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncyrattle.bcpg.BCPGInputStream;
import org.bouncyrattle.bcpg.Packet;
import org.bouncyrattle.bcpg.PacketTags;
import org.bouncyrattle.bcpg.PublicKeyPacket;
import org.bouncyrattle.bcpg.PublicSubkeyPacket;
import org.bouncyrattle.bcpg.SecretKeyPacket;
import org.bouncyrattle.bcpg.SecretSubkeyPacket;
import org.bouncyrattle.bcpg.SignaturePacket;
import org.bouncyrattle.bcpg.TrustPacket;
import org.bouncyrattle.bcpg.UserIDPacket;
import org.bouncyrattle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncyrattle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class CStrictKeyParser
{
    // fullkey true means I want a signing subkey as well.
    // expect_onesigner means there's one additional signature
    // on the master key.
    public final static PGPPublicKeyRing parsePublicKeyRing
        (InputStream inp, boolean fullkey, boolean expect_onesigner)
        throws IOException,PGPException
    {
        // Use the low-level APIs to handle a very specific subset
        // of acceptable public-key encodings.

        // convert to packets.
        BCPGInputStream packetStream = new BCPGInputStream(inp);

        Packet packet = packetStream.readPacket();
        if (!(packet instanceof PublicKeyPacket)) {
            throw new PGPException("Missing publickey packet.");
        }
        PublicKeyPacket masterpack = (PublicKeyPacket) packet;
        packet = packetStream.readPacket();
        if (!(packet instanceof UserIDPacket)) {
            throw new PGPException("Missing user-id packet.");
        }
        String uid = ((UserIDPacket) packet).getID();
        List<String> ids = Arrays.asList(uid);
        packet = packetStream.readPacket();
        if (!(packet instanceof SignaturePacket)) {
            throw new PGPException("Missing signature packet.");
        }
        ArrayList<ArrayList<PGPSignature>> idsigs =
            new ArrayList<ArrayList<PGPSignature>>();
        List<TrustPacket> idtrusts = new ArrayList<TrustPacket>();

        ArrayList<PGPSignature> idsig = new ArrayList<PGPSignature>();
        idsig.add(new PGPSignature((SignaturePacket) packet, null));
        if (expect_onesigner) {
            packet = packetStream.readPacket();
            if (!(packet instanceof SignaturePacket)) {
                throw new PGPException("Missing signature packet.");
            }
            idsig.add(new PGPSignature((SignaturePacket) packet, null));
        }

        idsigs.add(idsig);
        idtrusts.add(null);
        List<PGPPublicKey> keys = new ArrayList<PGPPublicKey>();
        KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
        keys.add
            (new PGPPublicKey
             (masterpack, null, new ArrayList<PGPSignature>(),
              ids, idtrusts, idsigs, fpcalc));

        if (fullkey) {
            packet = packetStream.readPacket();
            if (!(packet instanceof PublicSubkeyPacket)) {
                throw new PGPException("Missing public subkey packet.");
            }
            PublicSubkeyPacket subpack = (PublicSubkeyPacket) packet;
            packet = packetStream.readPacket();
            if (!(packet instanceof SignaturePacket)) {
                throw new PGPException("Missing public subkey signature.");
            }
            List<PGPSignature> subsigs =
                Arrays.asList
                (new PGPSignature((SignaturePacket) packet, null));
            keys.add
                (new PGPPublicKey
                 (subpack, null, subsigs, fpcalc));
            if (packetStream.readPacket() != null) {
                throw new PGPException("Extra data following key");
            }
        }
        return new PGPPublicKeyRing(keys);
    }

    public final static PGPSecretKeyRing parseSecretKeyRing (InputStream inp)
        throws IOException,PGPException
    {
        BCPGInputStream packetStream = new BCPGInputStream(inp);

        Packet packet = packetStream.readPacket();
        if (!(packet instanceof SecretKeyPacket)) {
            throw new PGPException("Missing secretkey packet.");
        }
        SecretKeyPacket masterpack = (SecretKeyPacket) packet;
        packet = packetStream.readPacket();
        if (!(packet instanceof UserIDPacket)) {
            throw new PGPException("Missing user-id packet.");
        }
        String uid = ((UserIDPacket) packet).getID();
        /* Not so strict, for now
        if (!PPL_MAGIC.equals(uid)) {
            throw new PGPException("user-id must be "+PPL_MAGIC);
        }
        */
        List<String> ids = Arrays.asList(uid);
        packet = packetStream.readPacket();
        if (!(packet instanceof SignaturePacket)) {
            throw new PGPException("Missing signature packet.");
        }
        ArrayList<ArrayList<PGPSignature>> idsigs =
            new ArrayList<ArrayList<PGPSignature>>();
        List<TrustPacket> idtrusts = new ArrayList<TrustPacket>();
        idsigs.add(asList(new PGPSignature((SignaturePacket) packet, null)));
        idtrusts.add(null);
        List<PGPSecretKey> keys = new ArrayList<PGPSecretKey>();
        KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
        keys.add
            (new PGPSecretKey
             (masterpack,
              new PGPPublicKey
              (masterpack.getPublicKeyPacket(),
               null, new ArrayList<PGPSignature>(),
               ids, idtrusts, idsigs, fpcalc)));

        packet = packetStream.readPacket();
        if (!(packet instanceof SecretSubkeyPacket)) {
            throw new PGPException("Missing secret subkey packet.");
        }
        SecretSubkeyPacket subpack = (SecretSubkeyPacket) packet;
        packet = packetStream.readPacket();
        if (!(packet instanceof SignaturePacket)) {
            throw new PGPException("Missing subkey signature.");
        }
        List<PGPSignature> subsigs =
            Arrays.asList
            (new PGPSignature((SignaturePacket) packet, null));
        keys.add
            (new PGPSecretKey
             (subpack,
              (new PGPPublicKey
               (subpack.getPublicKeyPacket(), null, subsigs, fpcalc))));
        if (packetStream.readPacket() != null) {
            throw new PGPException("Extra data following key");
        }
        return new PGPSecretKeyRing(keys);
    }

    private final static ArrayList<PGPSignature> asList(PGPSignature sig)
    {
        ArrayList<PGPSignature> ret = new ArrayList<PGPSignature>();
        ret.add(sig);
        return ret;
    }

    // public final static String PPL_MAGIC = "prettyprivatedrive";
}
