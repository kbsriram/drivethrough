package com.kbsriram.cli;

import com.kbsriram.common.drive.CDrive;
import com.kbsriram.common.pgp.CPGPUtils;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.bouncyrattle.openpgp.PGPKeyRingGenerator;
import org.bouncyrattle.openpgp.PGPPrivateKey;
import org.bouncyrattle.openpgp.PGPPublicKeyRing;
import org.bouncyrattle.openpgp.PGPSecretKeyRing;

public class CMain
{
    // java CMain setup <basedir>
    //   -> initialize a new thing.
    // java CMain pull <basedir>
    //   -> pull, decrypt and remote-delete new content.

    public static void main(String args[])
        throws Exception
    {
        if (args.length == 0) {
            usage();
            return;
        }

        if ("setup".equals(args[0])) {
            if (args.length != 2) {
                usage();
                return;
            }
            doSetup(args[1]);
            return;
        }
        if ("pull".equals(args[0])) {
            if (args.length != 2) {
                usage();
                return;
            }
            doPull(args[1]);
            return;
        }

        usage();
    }

    private final static void usage()
    {
        System.err.println("Usage: java drivethrough.jar\n"+
                           "\tsetup <basedir>\n"+
                           "\tpull <basedir>");
    }

    private final static void doSetup(String basepath)
        throws Exception
    {
        File basedir = new File(basepath);
        if (!basedir.isDirectory()) {
            basedir.mkdirs();
        }

        // Make sure we don't have any existing stuff.
        File pubfile = new File(basedir, "keys.pkr");
        File secfile = new File(basedir, "keys.skr");
        File configfile = new File(basedir, "config.properties");
        File accessfile = new File(basedir, "access.properties");

        if (pubfile.canRead() ||
            secfile.canRead() ||
            configfile.canRead()) {
            throw new IOException
                (basepath+" already has some content - not setting up.");
        }

        // Grab tokens from user.
        System.out.println();
        System.out.println("Paste this URL into a browser");
        System.out.println();
        System.out.println("https://accounts.google.com/o/oauth2/auth?response_type=code&client_id="+CDrive.CLIENT_ID+"&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope="+CDrive.SCOPE);
        System.out.println();
        System.out.print("Enter code from browser: ");
        System.out.flush();
        BufferedReader br =
            new BufferedReader(new InputStreamReader(System.in));
        String code;

        while ((code = br.readLine()) != null) {
            code = code.trim();
            if (code.length() == 0) {
                System.out.print("Enter code: ");
                System.out.flush();
                continue;
            }
            else { break; }
        }

        CDrive.Credentials cred = CDrive.mintOobCredentials(code);

        Properties config = new Properties();
        config.setProperty(REFRESH, cred.getRefresh());
        Properties access = new Properties();
        access.setProperty(ACCESS, cred.getAccess());

        // Check whether we already have a pubkey on the server.
        List<CDrive.File> remote_pubkeys = CDrive.getMainKeys(cred);
        if (remote_pubkeys.size() > 0) {
            throw new IOException
                ("Woops - server already has a main pubkey. Remove these first: "+remote_pubkeys);
        }

        // Generate a new pubkey
        char[] pw = CPGPUtils.genRandom(40);
        config.setProperty(PASSWORD, new String(pw));
        PGPKeyRingGenerator pkrg = CPGPUtils.generateKeyRingGenerator
            ("master-key", pw, 0x60);

        PGPPublicKeyRing pkr = pkrg.generatePublicKeyRing();
        PGPSecretKeyRing skr = pkrg.generateSecretKeyRing();

        BufferedOutputStream bout =
            new BufferedOutputStream
            (new FileOutputStream(pubfile));
        pkr.encode(bout);
        bout.close();
        bout =
            new BufferedOutputStream
            (new FileOutputStream(secfile));
        skr.encode(bout);
        bout.close();

        // the root directory.
        CDrive.File drive_root = CDrive.makeOrGetRoot(cred);

        // upload
        CDrive.File remote_pkr = CDrive.upload
            (cred, pubfile, "main.pkr", CDrive.TYPE_MAIN_PUBKEY,
             drive_root.getId());

        // Now flush out config.
        BufferedWriter bw =
            new BufferedWriter
            (new FileWriter(configfile));
        config.store(bw, "main configuration");
        bw.close();

        bw =
            new BufferedWriter
            (new FileWriter(accessfile));
        access.store(bw, "current access token");
        bw.close();

        System.out.println();
        System.out.println("Setup completed successfully.");
    }

    private final static void doPull(String basepath)
        throws Exception
    {
        File basedir = new File(basepath);
        if (!basedir.isDirectory()) {
            throw new FileNotFoundException(basepath);
        }

        // Load config and keys.
        File pubfile = new File(basedir, "keys.pkr");
        File secfile = new File(basedir, "keys.skr");
        File configfile = new File(basedir, "config.properties");
        File accessfile = new File(basedir, "access.properties");

        if (!pubfile.canRead() ||
            !secfile.canRead() ||
            !configfile.canRead() ||
            !accessfile.canRead()) {
            throw new IOException
                (basepath+" missing expected files");
        }

        BufferedReader br =
            new BufferedReader
            (new InputStreamReader
             (new FileInputStream(configfile)));
        Properties config = new Properties();
        config.load(br);
        br.close();

        String refresh = config.getProperty(REFRESH);
        String pw = config.getProperty(PASSWORD);
        if ((refresh == null) || (pw == null)) {
            throw new IOException("Missing properties in config");
        }

        br =
            new BufferedReader
            (new InputStreamReader
             (new FileInputStream(accessfile)));
        Properties access_config = new Properties();
        access_config.load(br);
        br.close();
        String access = access_config.getProperty(ACCESS);
        if (access == null) {
            throw new IOException("Missing properties in config");
        }

        PGPPrivateKey enc_key = extractEncryptionKey(secfile, pw);

        CDrive.Credentials cred = new CDrive.Credentials(refresh, access);

        refreshDeviceKeys(cred, basedir);

        // flush any new access tokens
        if (!access.equals(cred.getAccess())) {
            access_config.setProperty(ACCESS, cred.getAccess());
            BufferedWriter
                bw =
                new BufferedWriter
                (new FileWriter(accessfile));
            access_config.store(bw, "current access token");
            bw.close();
        }

        List<PGPPublicKeyRing> signers = loadSigners(basedir);
        if (signers.size() == 0) {
            System.out.println("No devicekeys - stop");
            return;
        }

        pullEncryptedFiles(cred, basedir, signers, enc_key);
    }

    private final static List<PGPPublicKeyRing> loadSigners(File basedir)
        throws Exception
    {
        List<PGPPublicKeyRing> ret = new ArrayList<PGPPublicKeyRing>();
        File droot = new File(basedir, DEVICE_DIR);
        if (!droot.isDirectory()) { return ret; }
        File[] children = droot.listFiles();
        if (children == null) { return ret; }
        for (int i=0; i<children.length; i++) {
            File child = children[i];
            String n = child.getName();
            if (n.endsWith(".pkr")) {
                ret.add(readPublicKeyRing(child));
            }
        }
        return ret;
    }

    private final static void refreshDeviceKeys
        (CDrive.Credentials cred, File basedir)
        throws Exception
    {
        List<CDrive.File> remote_devkeys = CDrive.getDeviceKeys(cred);

        File local_devkeyroot = new File(basedir, DEVICE_DIR);
        if (!local_devkeyroot.isDirectory()) {
            local_devkeyroot.mkdirs();
        }
        for (CDrive.File remote_devkey: remote_devkeys) {
            File local_devkey =
                new File(local_devkeyroot, remote_devkey.getTitle());
            if (local_devkey.canRead()) {
                // check timestamp.
                long remote_ts = remote_devkey.getModified().getValue();

                // hack - timestamps only in seconds, sigh.
                long local_ts = local_devkey.lastModified() + 1000l;
                if (local_ts >= remote_ts) {
                    if (remote_devkey.getSize() == local_devkey.length()) {
                        continue;
                    }
                }
            }
            File tmp = File.createTempFile("drvthru", "pkr");
            try {
                CDrive.download
                    (new URL(remote_devkey.getDownloadUrl()), cred, tmp);

                // Load and check
                PGPPublicKeyRing dev_pkr = readPublicKeyRing(tmp);

                if (!(CPGPUtils.asFingerprint(dev_pkr)+".pkr").equals
                    (remote_devkey.getTitle())) {
                    System.err.println
                        ("WARN: skip mismatched dev-key: "+
                         remote_devkey.getTitle());
                }
                else {
                    copy(tmp, local_devkey);
                    local_devkey.setLastModified
                        (remote_devkey.getModified().getValue());
                }
            }
            finally {
                tmp.delete();
            }
        }
    }

    private final static void pullEncryptedFiles
        (CDrive.Credentials cred, File basedir,
         List<PGPPublicKeyRing> signers, PGPPrivateKey enc_key)
        throws Exception
    {
        List<CDrive.File> remote_files = CDrive.getEncryptedFiles(cred);

        for (CDrive.File remote_file: remote_files) {
            File tmp_src = File.createTempFile("drvthru", "pgp");
            File tmp_dst = File.createTempFile("drvthru", "pgp");
            BufferedInputStream bin = null;
            BufferedOutputStream bout = null;
            try {
                // 1. Download
                CDrive.download
                    (new URL(remote_file.getDownloadUrl()), cred, tmp_src);

                // 2. Decrypt
                bin = new BufferedInputStream
                    (new FileInputStream(tmp_src));
                bout = new BufferedOutputStream
                    (new FileOutputStream(tmp_dst));

                CPGPUtils.FileInfo finfo =
                    CPGPUtils.extractEncryptedData(bin, signers, enc_key, bout);
                bin.close();
                bin = null;
                bout.close();
                bout = null;

                // 3. Move into suitable local destination.
                File local_dst =
                    new File
                    (basedir+"/"+
                     CPGPUtils.asFingerprint(finfo.getSignerKeyRing())+"/"+
                     finfo.getFileName());

                System.out.println("Move into "+local_dst);

                // make any needed paths
                local_dst.getParentFile().mkdirs();
                copy(tmp_dst, local_dst);
                local_dst.setLastModified(finfo.getModified().getTime());
                // remove the remote file as well.
                CDrive.delete(cred, remote_file.getId());
            }
            finally {
                tmp_src.delete();
                tmp_dst.delete();
            }
        }
    }

    private final static void copy(File src, File dest)
        throws IOException
    {
        FileInputStream fin = new FileInputStream(src);
        FileOutputStream fout = new FileOutputStream(dest);
        byte buf[] = new byte[8192];
        int nread;
        while ((nread = fin.read(buf)) > 0) {
            fout.write(buf, 0, nread);
        }
        fin.close();
        fout.close();
    }

    private final static PGPPublicKeyRing readPublicKeyRing(File src)
        throws Exception
    {
        BufferedInputStream bin = null;
        try {
            bin =
                new BufferedInputStream
                (new FileInputStream(src));
            return CPGPUtils.readPublicKeyRing(bin, true);
        }
        finally {
            if (bin != null) {
                try { bin.close(); }
                catch (IOException ign) {}
            }
        }
    }

    private final static PGPPrivateKey extractEncryptionKey
        (File src, String pw)
        throws Exception
    {
        BufferedInputStream bin = null;
        try {
            bin =
                new BufferedInputStream
                (new FileInputStream(src));
            PGPSecretKeyRing skr = CPGPUtils.readSecretKeyRing(bin);
            return CPGPUtils.extractPrivateKey
                (CPGPUtils.getEncryptionKey(skr), pw.toCharArray());
        }
        finally {
            if (bin != null) {
                try { bin.close(); }
                catch (IOException ign) {}
            }
        }
    }

    private final static String DEVICE_DIR = "device_keys";
    private final static String REFRESH = "refresh";
    private final static String ACCESS = "access";
    private final static String PASSWORD = "password";
}
