import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This class should store all the data provided by the 12 byte DNS header
 */
public class DNSHeader {
    private int id_;        // 16 bit identifier
    private boolean qr_;    // 1 bit (0 for query and 1 for response)
    private int opcode_;    // 4 bit opcode to identify type of query
    private boolean aa_;    // 1 bit "authoritative answer" specifies whether the responding name server is an authority for the domain name in question section
    private boolean tc_;    // 1 bit "truncation" specifies whether this message was truncated
    private boolean rd_;    // 1 bit "recursion desired"
    private boolean ra_;    // 1 bit "recursion available"
    private boolean z_;     // 1 bit reserved for future use
    private boolean ad_;    // 1 bit "authenticated data"
    private boolean cd_;    // 1 bit "checking disabled"
    private int rcode_;     // 4 bits to identify type of response
    private int qdcount_;   // an unsigned 16 bit integer specifying the number of entries in the question section
    private int ancount_;   // an unsigned 16 bit integer specifying the number of resource records in the answer section
    private int nscount_;   // an unsigned 16 bit integer specifying the number of name server resource records in the authority records section
    private int arcount_;   // an unsigned 16 bit integer specifying the number of resource records in the additional records section.

    /**
     * read and parse the header from an input stream
     *
     * @param input - stream to read and parse from
     * @return DNSHeader with all info parsed
     */
    public static DNSHeader decodeHeader(InputStream input) throws IOException {
        DNSHeader header = new DNSHeader();

        // parse id
        byte[] id = input.readNBytes(2);
        header.id_ = ((id[0] & 0xff) << 8) | (id[1] & 0xff);

        // parse flags, opcode, and rcode
        int byte3 = input.read();
        header.qr_ = (byte3 & 0x80) != 0;
        header.opcode_ = (byte3 & 0x78) >> 3;
        header.aa_ = (byte3 & 0x04) != 0;
        header.tc_ = (byte3 & 0x02) != 0;
        header.rd_ = (byte3 & 0x01) != 0;

        int byte4 = input.read();
        header.ra_ = (byte4 & 0x80) != 0;
        header.z_ = (byte4 & 0x40) != 0;
        header.ad_ = (byte4 & 0x20) != 0;
        header.cd_ = (byte4 & 0x10) != 0;
        header.rcode_ = byte4 & 0xf;

        // parse qdcount
        byte[] qdcount = input.readNBytes(2);
        header.qdcount_ = ((qdcount[0] & 0xff) << 8) | (qdcount[1] & 0xff);

        // parse ancount
        byte[] ancount = input.readNBytes(2);
        header.ancount_ = ((ancount[0] & 0xff) << 8) | (ancount[1] & 0xff);

        // parse nscount
        byte[] nscount = input.readNBytes(2);
        header.nscount_ = ((nscount[0] & 0xff) << 8) | (nscount[1] & 0xff);

        //parse arcount
        byte[] arcount = input.readNBytes(2);
        header.arcount_ = ((arcount[0] & 0xff) << 8) | (arcount[1] & 0xff);

        return header;
    }

    /**
     * create a standard header for the response
     * will copy some fields from the request and will hard code other fields based on standard response header
     *
     * Note: this will not be used to create a header for a response regarding a nonexistent domain because the
     * response to a nonexistent domain will be forwarded directly, uninterrupted from Google to the client
     *
     * @param request - request to copy some header fields from
     * @return DNSHeader for a response to the provided request
     */
    public static DNSHeader buildResponseHeader(DNSMessage request) {
        DNSHeader header = new DNSHeader();
        // using most of the header values that I get from Google as a standard header
        // only id and qdcount come from the corresponding request
        header.id_ = request.getHeader().getID();
        header.qr_ = true;
        header.opcode_ = 0;
        header.aa_ = false;
        header.tc_ = false;
        header.rd_ = true;
        header.ra_ = true;
        header.z_ = false;
        header.ad_ = true;
        header.cd_ = false;
        header.rcode_ = 0;
        header.qdcount_ = request.getHeader().qdcount_;
        header.ancount_ = 1;
        header.nscount_ = 0;
        header.arcount_ = 1;

        return header;
    }

    /**
     * convert the DNSHeader to bytes and write to the output stream
     *
     * @param output - stream to write bytes to
     */
    public void writeBytes(OutputStream output) throws IOException {
        // write id
        int byte1 = (id_ >> 8) & 0xff;
        output.write(byte1);
        int byte2 = id_ & 0xff;
        output.write(byte2);
        // write flags, opcode, and rcode
        int qr = (qr_) ? 1 : 0;
        int aa = (aa_) ? 1 : 0;
        int tc = (tc_) ? 1 : 0;
        int rd = (rd_) ? 1 : 0;
        int byte3 = ((qr << 7) | (opcode_ << 3) | (aa << 2) | (tc << 1) | rd);
        output.write(byte3);
        int ra = (ra_) ? 1 : 0;
        int z = (z_) ? 1 : 0;
        int ad = (ad_) ? 1 : 0;
        int cd = (cd_) ? 1 : 0;
        int byte4 = ((ra << 7) | (z << 6) | (ad << 5) | (cd << 4) | rcode_);
        output.write(byte4);
        // write qdcount
        int byte5 = (qdcount_ >> 8) & 0xff;
        output.write(byte5);
        int byte6 = qdcount_ & 0xff;
        output.write(byte6);
        // write ancount
        int byte7 = (ancount_ >> 8) & 0xff;
        output.write(byte7);
        int byte8 = ancount_ & 0xff;
        output.write(byte8);
        // write nscount
        int byte9 = (nscount_ >> 8) & 0xff;
        output.write(byte9);
        int byte10 = nscount_ & 0xff;
        output.write(byte10);
        // write arcount
        int byte11 = (arcount_ >> 8) & 0xff;
        output.write(byte11);
        int byte12 = arcount_ & 0xff;
        output.write(byte12);
    }

    // auto-generated functions
    @Override
    public String toString() {
        return "DNSHeader{" +
                "id_=" + id_ +
                ", qr_=" + qr_ +
                ", opcode_=" + opcode_ +
                ", aa_=" + aa_ +
                ", tc_=" + tc_ +
                ", rd_=" + rd_ +
                ", ra_=" + ra_ +
                ", z_=" + z_ +
                ", ad_=" + ad_ +
                ", cd_=" + cd_ +
                ", rcode_=" + rcode_ +
                ", qdcount_=" + qdcount_ +
                ", ancount_=" + ancount_ +
                ", nscount_=" + nscount_ +
                ", arcount_=" + arcount_ +
                '}';
    }

    public int getID() {
        return id_;
    }

    public int getRcode_() {
        return rcode_;
    }

    public int getQDcount() {
        return qdcount_;
    }

    public int getANcount() {
        return ancount_;
    }

    public int getNScount() {
        return nscount_;
    }

    public int getARcount() {
        return arcount_;
    }
}
