package com.kbsriram.common.drive;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public final class CDrive
{
    public interface Logger
    {
        public void logd(String tag, String m);
        public void logw(String tag, String m);
        public void logw(String tag, String m, Throwable e);
    }

    @SuppressWarnings("serial")
    public final static class ResponseException
        extends IOException
    {
        private ResponseException(int code, String content, String auth)
        {
            super("failed with error-code: "+code);
            m_code = code;
            m_content = content;
            m_auth = auth;
            m_needs_refresh = false;
        }
        public int getCode()
        { return m_code; }
        public String getContent()
        { return m_content; }
        public String getAccess()
        { return m_auth; }
        public boolean needsRefresh()
        { return m_needs_refresh; }
        public String toString()
        { return "ERROR: "+m_code+"\n\n"+m_content; }
        private void setNeedsRefresh(boolean v)
        { m_needs_refresh = v; }
        private final int m_code;
        private final String m_content;
        private final String m_auth;
        private boolean m_needs_refresh = false;
    }

    public final static class File
    {
        private final static CDrive.File newFromJSON(JSONObject js)
            throws JSONException
        {
            return new CDrive.File
                (js.getString(F_ID),
                 Long.parseLong(js.optString(F_FILE_SIZE, "0")),
                 js.getString(F_TITLE),
                 js.optString(F_DOWNLOAD_URL, null),
                 CDateTime.parseRfc3339(js.getString(F_CREATED_DATE)),
                 CDateTime.parseRfc3339(js.getString(F_MODIFIED_DATE)));
        }
        private File
            (String id, long size, String title, String dlurl,
             CDateTime created, CDateTime modified)
        {
            m_id = id;
            m_size = size;
            m_title = title;
            m_dlurl = dlurl;
            m_created = created;
            m_modified = modified;
        }
        public String getId() { return m_id; }
        public long getSize() { return m_size; }
        public String getTitle() { return m_title; }
        public String getDownloadUrl() { return m_dlurl; }
        public CDateTime getCreated() { return m_created; }
        public CDateTime getModified() { return m_modified; }
        public String toString()
        {
            return
                "{'id': '"+m_id+"','size':"+m_size+
                ",'title':'"+m_title+"','downloadURL':"+m_dlurl+"'}";
        }

        private final String m_id;
        private final long m_size;
        private final String m_title;
        private final String m_dlurl;
        private final CDateTime m_created;
        private final CDateTime m_modified;
    }

    public final static class Credentials
    {
        public Credentials(String refresh, String access)
        {
            m_refresh = refresh;
            m_access = access;
        }
        public String getAccess()
        { return m_access; }
        public String getRefresh()
        { return m_refresh; }
        public void setAccess(String v)
        { m_access = v; }
        private final String m_refresh;
        private String m_access;
    }

    public final static void setLogger(Logger logger)
    { s_logger = logger; }

    public final static Credentials mintOobCredentials(String code)
        throws IOException, JSONException
    {
        Map<String,String> kv = new HashMap<String,String>();
        kv.put("client_id", CLIENT_ID);
        kv.put("client_secret", CLIENT_SECRET);
        kv.put("code", code);
        kv.put("redirect_uri", "urn:ietf:wg:oauth:2.0:oob");
        kv.put("grant_type", "authorization_code");
        JSONObject ret = postJSONObject(new URL(URL_OAUTH), kv);
        return new Credentials
            (ret.getString("refresh_token"),
             ret.getString("access_token"));
    }

    public final static void delete(Credentials cred, String fileid)
        throws IOException, JSONException
    {
        URL url = new URL(URL_FILES+"/"+fileid);

        try { doDelete(url, cred.getAccess()); }
        catch (ResponseException re) {
            if (couldRefresh(re, cred)) {
                doDelete(url, cred.getAccess());
            }
            else {
                throw re;
            }
        }
    }

    public final static CDrive.File upload
        (Credentials cred, java.io.File src, String name, String mime,
         String parentId)
        throws IOException, JSONException
    {
        JSONObject meta = new JSONObject();
        meta.put(F_TITLE, name);
        meta.put(F_MIME_TYPE, mime);
        if (parentId != null) {
            meta.put(F_PARENTS, id2JSON(parentId));
        }
        return CDrive.File.newFromJSON
            (uploadJSONObject(new URL(URL_UPLOADS), cred, src, meta));
    }

    public final static void download
        (URL url, Credentials cred, java.io.File dest)
        throws IOException, JSONException
    {
        // wrap around a single retry, for expired tokens.
        try { doDownload(url, cred.getAccess(), dest); }
        catch (ResponseException re) {
            if (couldRefresh(re, cred)) {
                doDownload(url, cred.getAccess(), dest);
            }
            else {
                throw re;
            }
        }
    }

    private final static void doDownload
        (URL url, String auth, java.io.File dest)
        throws IOException
    {
        int tries = 0;
        while (tries <= 5) {
            tries++;
            HttpURLConnection con = (HttpURLConnection) (url.openConnection());
            s_logger.logd("cdrive", "downloading "+url+" to "+dest);
            InputStream in = null;
            FileOutputStream fout = null;
            boolean ok = false;
            try {
                con.setInstanceFollowRedirects(false);
                if (auth != null) {
                    con.setRequestProperty("Authorization", "Bearer "+auth);
                }

                int rcode = con.getResponseCode();
                if (rcode < 300) {
                    fout = new FileOutputStream(dest);
                    in = con.getInputStream();
                    byte[] buf = new byte[BUF_SIZE];
                    int nread;
                    long last_status = System.currentTimeMillis();
                    long cum = 0l;
                    while ((nread = in.read(buf)) > 0) {
                        fout.write(buf, 0, nread);
                        cum += nread;
                        long now = System.currentTimeMillis();
                        if ((now - last_status) > 10000l) {
                            s_logger.logd
                                ("cdrive", "downloaded "+cum+" bytes");
                            last_status = now;
                        }
                    }
                    ok = true;
                    return;
                }
                else {
                    throw asResponseException(rcode, con, auth);
                }
            }
            catch (IOException ex) {
                if (isTransientException(ex) && (tries <= 5)) {
                    int waitsec = (1 << tries);
                    s_logger.logd
                        ("cdrive", "pause for "+waitsec+" seconds");
                    try { Thread.sleep(waitsec*1000l); }
                    catch (InterruptedException ie) {}
                    continue;
                }
                throw ex;
            }
            finally {
                if (in != null) {
                    try { in.close(); }
                    catch (IOException ioe) {}
                }
                if (fout != null) {
                    try { fout.close(); }
                    catch (IOException ioe) {}
                }
                if (!ok) { dest.delete(); }
            }
        }
    }

    // Given a "/" separated path, Creates any missing components
    // and returns the last.
    public static CDrive.File makeOrGetRoot(Credentials cred)
        throws IOException, JSONException
    { return makeOrGetDirectory(cred, DRIVETHROUGH_ROOT_NAME); }

    public static CDrive.File makeOrGetDirectory(Credentials cred, String path)
        throws IOException, JSONException
    {
        String[] components = path.split("/");
        int len = components.length;

        CDrive.File curfile = null;
        for (int i=0; i<len; i++) {
            String name = components[i];
            if (name.length() == 0) { continue; }
            StringBuilder q = new StringBuilder();
            q.append(F_TITLE);
            q.append("='");
            q.append(name);
            q.append("' and ");
            q.append(F_MIME_TYPE);
            q.append("='");
            q.append(TYPE_DRIVE_FOLDER);
            q.append("'");
            if (curfile != null) {
                q.append(" and '");
                q.append(curfile.getId());
                q.append("' in parents");
            }
            List<CDrive.File> tmp = search(cred, q.toString());
            if (tmp.size() == 0) {
                curfile = createDirectory(cred, name, curfile);
            }
            else {
                curfile = tmp.get(0);
            }
        }
        return curfile;
    }

    public static List<CDrive.File> getMainKeys(Credentials cred)
        throws JSONException, IOException
    { return search(cred, F_MIME_TYPE+"='"+TYPE_MAIN_PUBKEY+"'"); }

    public static List<CDrive.File> getDeviceKeys(Credentials cred)
        throws JSONException, IOException
    { return search(cred, F_MIME_TYPE+"='"+TYPE_DEVICE_PUBKEY+"'"); }

    public static List<CDrive.File> getEncryptedFiles(Credentials cred)
        throws JSONException, IOException
    { return search(cred, F_MIME_TYPE+"='"+TYPE_ENCRYPTED+"'"); }

    public static List<CDrive.File> search(Credentials cred, String query)
        throws JSONException, IOException
    {
        StringBuilder q = new StringBuilder();
        q.append("trashed=false");
        if (query != null) {
            q.append(" and ");
            q.append(query);
        }
        String fields = "items("+
            F_ID+","+F_FILE_SIZE+","+F_TITLE+","+F_CREATED_DATE+","+
            F_MODIFIED_DATE+","+F_DOWNLOAD_URL+")";

        StringBuilder sb = new StringBuilder(URL_FILES);
        addQuery(sb, "q", q.toString(), true);
        addQuery(sb, "fields", fields, false);

        JSONObject result = getJSONObject(new URL(sb.toString()), cred);
        List<CDrive.File> ret = new ArrayList<CDrive.File>();
        JSONArray jsa = result.optJSONArray("items");
        if (jsa != null) {
            int len = jsa.length();
            for (int i=0; i<len; i++) {
                ret.add(CDrive.File.newFromJSON(jsa.getJSONObject(i)));
            }
        }
        return ret;
    }

    private static JSONArray id2JSON(String id)
        throws JSONException
    {
        JSONArray ret = new JSONArray();
        JSONObject js = new JSONObject();
        js.put(F_ID, id);
        ret.put(js);
        return ret;
    }

    private static CDrive.File createDirectory
        (Credentials cred, String name, CDrive.File under)
        throws IOException, JSONException
    {
        JSONObject njs = new JSONObject();
        njs.put(F_TITLE, name);
        njs.put(F_MIME_TYPE, TYPE_DRIVE_FOLDER);
        if (under != null) {
            njs.put(F_PARENTS, id2JSON(under.getId()));
        }
        return CDrive.File.newFromJSON
            (expectJSONObject(new URL(URL_FILES), cred, njs));
    }

    private final static JSONObject getJSONObject(URL url)
        throws IOException, JSONException
    { return expectJSONObject(url, null, null, null); }

    private final static JSONObject getJSONObject(URL url, Credentials cred)
        throws IOException, JSONException
    { return expectJSONObject(url, cred, null, null); }

    // Form post; no auth.
    private final static JSONObject postJSONObject
        (URL url, Map<String, String> params)
        throws IOException, JSONException
    {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String k: params.keySet()) {
            if (first) { first = false; }
            else { sb.append("&"); }
            sb.append(k);
            sb.append("=");
            sb.append(params.get(k));
        }
        return doExpectJSONObject
            (url, null, sb.toString(), "application/x-www-form-urlencoded");
    }

    // JSON post with auth.
    private final static JSONObject expectJSONObject
        (URL url, Credentials cred, JSONObject send)
        throws IOException, JSONException
    {
        return expectJSONObject
            (url, cred, send.toString(), "application/json");
    }

    private final static boolean couldRefresh
        (ResponseException re, Credentials cred)
        throws IOException, JSONException
    {
        if (re.getCode() != 401) { return false; }
        if (re.getContent().indexOf("Invalid Credentials") <= 0) {
            return false;
        }
        re.setNeedsRefresh(true);
        if (cred.getRefresh() == null) {
            return false;
        }
        Map<String,String> kv = new HashMap<String,String>();
        kv.put("client_id", CLIENT_ID);
        kv.put("client_secret", CLIENT_SECRET);
        kv.put("refresh_token", cred.getRefresh());
        kv.put("grant_type", "refresh_token");
        JSONObject ret = postJSONObject(new URL(URL_OAUTH), kv);
        String access = ret.optString("access_token");
        if (access == null) { return false; }
        cred.setAccess(access);
        return true;
    }

    private final static JSONObject uploadJSONObject
        (URL url, Credentials cred, java.io.File src, JSONObject meta)
        throws IOException, JSONException
    {
        // wrap around a single retry, for expired tokens.
        try { return doUploadJSONObject(url, cred.getAccess(), src, meta); }
        catch (ResponseException re) {
            if (couldRefresh(re, cred)) {
                return doUploadJSONObject(url, cred.getAccess(), src, meta);
            }
            else {
                throw re;
            }
        }
    }

    private final static JSONObject doUploadJSONObject
        (URL url, String auth, java.io.File src, JSONObject meta)
        throws IOException, JSONException
    {
        int tries = 0;
        while (true) {
            s_logger.logd("cdrive", "Upload to "+url);
            tries++;
            FileInputStream fin = null;
            HttpURLConnection con = (HttpURLConnection) (url.openConnection());

            OutputStream out = null;
            try {
                fin = new FileInputStream(src);
                con.setChunkedStreamingMode(BUF_SIZE*2);
                con.setInstanceFollowRedirects(false);
                if (auth != null) {
                    con.setRequestProperty("Authorization", "Bearer "+auth);
                }

                con.setDoOutput(true);
                con.setRequestProperty
                    ("Content-Type",
                     "multipart/related; boundary=\""+BOUNDARY+"\"");

                out = con.getOutputStream();
                OutputStreamWriter outw = new OutputStreamWriter(out);
                writeHeader(outw, "application/json");
                outw.write(meta.toString());
                outw.write(NL);

                writeHeader(outw, meta.getString(F_MIME_TYPE));
                outw.flush();

                byte[] buf = new byte[BUF_SIZE];
                int nread;
                long last_status = System.currentTimeMillis();
                long cum = 0l;
                while ((nread = fin.read(buf)) > 0) {
                    out.write(buf, 0, nread);
                    cum += nread;
                    long now = System.currentTimeMillis();
                    if ((now - last_status) > 10000l) {
                        s_logger.logd("cdrive", "uploaded "+cum+" bytes");
                        last_status = now;
                    }
                }
                out.flush();
                outw.write(NL);
                outw.write(TWO_HYPHEN); outw.write(BOUNDARY);
                outw.write(TWO_HYPHEN); outw.write(NL);
                outw.flush();
                return asJSONResponse(con, auth);
            }
            catch (IOException ex) {
                if (isTransientException(ex) && (tries <= 5)) {
                    int waitsec = (1 << tries);
                    s_logger.logd("cdrive", "pause for "+waitsec+" seconds");
                    try { Thread.sleep(waitsec*1000l); }
                    catch (InterruptedException ie) {}
                    continue;
                }
                throw ex;
            }
            finally {
                if (out != null) {
                    try { out.close(); }
                    catch (Throwable ign) {}
                }
                if (fin != null) {
                    try { fin.close(); }
                    catch (Throwable ign) {}
                }
            }
        }
    }

    private static void addQuery
        (StringBuilder sb, String n, String v, boolean first)
        throws IOException
    {
        if (first) { sb.append("?"); }
        else { sb.append("&"); }
        sb.append(n);
        sb.append("=");
        sb.append(URLEncoder.encode(v, "utf-8"));
    }

    private final static void writeHeader(OutputStreamWriter outw, String mime)
        throws IOException
    {
        outw.write(TWO_HYPHEN); outw.write(BOUNDARY); outw.write(NL);
        outw.write("Content-Type: ");
        outw.write(mime);
        outw.write(NL);
        outw.write(NL);
    }

    private final static JSONObject expectJSONObject
        (URL url, Credentials cred, String send, String mime)
        throws IOException, JSONException
    {
        // wrap around a single retry, for expired tokens.
        try { return doExpectJSONObject(url, cred.getAccess(), send, mime); }
        catch (ResponseException re) {
            if (couldRefresh(re, cred)) {
                return doExpectJSONObject(url, cred.getAccess(), send, mime);
            }
            else {
                throw re;
            }
        }
    }

    private final static void doDelete(URL url, String auth)
        throws IOException
    {
        s_logger.logd("cdrive", "delete "+url);
        HttpURLConnection con = (HttpURLConnection) (url.openConnection());
        con.setInstanceFollowRedirects(false);
        con.setRequestMethod("DELETE");
        if (auth != null) {
            con.setRequestProperty("Authorization", "Bearer "+auth);
        }
        asStringResponse(con, auth);
    }

    private final static JSONObject doExpectJSONObject
        (URL url, String auth, String send, String mime)
        throws IOException, JSONException
    {
        int tries = 0;
        while (true) {
            tries++;
            s_logger.logd("cdrive", "Open connection to "+url);
            HttpURLConnection con = (HttpURLConnection) (url.openConnection());

            OutputStreamWriter out = null;
            try {
                con.setInstanceFollowRedirects(false);
                if (auth != null) {
                    con.setRequestProperty("Authorization", "Bearer "+auth);
                }
                if (send != null) {
                    con.setDoOutput(true);
                    con.setRequestProperty("Content-Type", mime);
                    out = new OutputStreamWriter(con.getOutputStream());
                    s_logger.logd("cdrive", ">>>");
                    s_logger.logd("cdrive", send);
                    s_logger.logd("cdrive", "---");
                    out.write(send);
                    out.flush();
                }
                return asJSONResponse(con, auth);
            }
            catch (IOException ex) {
                if (isTransientException(ex) && (tries <= 5)) {
                    int waitsec = (1 << tries);
                    s_logger.logd("cdrive", "pause for "+waitsec+" seconds");
                    try { Thread.sleep(waitsec*1000l); }
                    catch (InterruptedException ie) {}
                    continue;
                }
                throw ex;
            }
            finally {
                if (out != null) {
                    try { out.close(); }
                    catch (Throwable ign) {}
                }
            }
        }
    }

    private static JSONObject asJSONResponse
        (HttpURLConnection con, String auth)
        throws IOException, JSONException
    { return new JSONObject(asStringResponse(con, auth)); }

    private static String asStringResponse
        (HttpURLConnection con, String auth)
        throws IOException
    {
        int rcode = con.getResponseCode();

        BufferedReader br = null;

        try {
            if (rcode < 300) {
                br =
                    new BufferedReader
                    (new InputStreamReader
                     (con.getInputStream()));
                String ret = asString(br);
                s_logger.logd("cdrive", ret);
                return ret;
            }
            else {
                throw asResponseException(rcode, con, auth);
            }
        }
        finally {
            if (br != null) {
                try { br.close(); }
                catch (IOException ioe) {}
            }
        }
    }

    private final static ResponseException asResponseException
        (int rcode, HttpURLConnection con, String auth)
        throws IOException
    {
        BufferedReader br = null;
        try {
            br =
                new BufferedReader
                (new InputStreamReader
                 (con.getErrorStream()));
            String content = asString(br);
            s_logger.logw("cdrive", "Failed: code="+rcode);
            s_logger.logw("cdrive", content);
            return new ResponseException(rcode, content, auth);
        }
        finally {
            if (br != null) {
                try { br.close(); }
                catch (IOException ign) {}
            }
        }
    }

    private final static boolean isTransientException(Exception ex)
    {
        if (ex instanceof ResponseException) {
            ResponseException re = (ResponseException) ex;
            return ((re.getCode() >= 500) && (re.getCode() <= 599));
        }
        else if (ex instanceof IOException) {
            // pretend this is transient too.
            return true;
        }
        else {
            return false;
        }
    }

    private static String asString(BufferedReader r)
        throws IOException
    {
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    private final static String BOUNDARY = "qpze5KG3Q9SshpV9vzGKxUyS";
    private final static String NL = "\r\n";
    private final static String TWO_HYPHEN = "--";
    private final static int BUF_SIZE = 4096;

    private final static String URL_FILES =
        "https://www.googleapis.com/drive/v2/files";
    private final static String URL_UPLOADS =
        "https://www.googleapis.com/upload/drive/v2/files?uploadType=multipart";
    private final static String URL_OAUTH =
        "https://accounts.google.com/o/oauth2/token";

    private final static String F_TITLE = "title";
    private final static String F_PARENTS = "parents";
    public final static String F_MIME_TYPE = "mimeType";
    private final static String F_ID = "id";
    private final static String F_FILE_SIZE = "fileSize";
    private final static String F_DOWNLOAD_URL = "downloadUrl";
    private final static String F_CREATED_DATE = "createdDate";
    private final static String F_MODIFIED_DATE = "modifiedDate";
    private final static String TYPE_DRIVE_FOLDER =
        "application/vnd.google-apps.folder";

    // Please - feel free to use, but don't do anything script-kiddy
    // with it.
    private final static String CLIENT_SECRET = "T5HNGlNq7-QKdeaI8hOUcfO8";
    private final static String DRIVETHROUGH_ROOT_NAME = "drivethrough";

    private static Logger s_logger = new Logger() {
            public void logd(String tag, String m)
            { System.out.println(tag+": "+m); }
            public void logw(String tag, String m)
            { System.err.println("WARN: "+tag+": "+m); }
            public void logw(String tag, String m, Throwable th)
            {
                System.err.println("WARN: "+tag+": "+m);
                th.printStackTrace();
            }
        };

    public final static String TYPE_MAIN_PUBKEY =
        "application/vnd.drivethrough.main.public_key";
    public final static String TYPE_DEVICE_PUBKEY =
        "application/vnd.drivethrough.device.public_key";
    public final static String TYPE_ENCRYPTED =
        "application/vnd.drivethrough.encrypted";
    public final static String CLIENT_ID = "276295963802-sh8ampbrr8g7ubbhhh6dcnkgq428cdl4.apps.googleusercontent.com";
    public final static String SCOPE = "https://www.googleapis.com/auth/drive";
}
