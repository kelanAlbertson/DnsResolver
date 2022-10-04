import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

/**
 * This class represents a record in a DNS message
 * This could be a question, answer, authoritative name serve, or additional record
 */
public class DNSRecord {
    private String name_;   // domain name
    private int type_;      // unsigned 16 bit rrtype code
    private int rclass_;    // unsigned 16 bit rr class code
    private int ttl_;       // unsigned 32 bit time to live
    private int rdlength_;  // unsigned 16 bit int representing the length of the following data
    private String rdata_;  // packet data of length rdlength
    private Date date_;     // the time and date of this record's creation to use as a timestamp with the TTL


    /**
     * read and parse a record from an input stream
     *
     * @param input - stream to read and parse from
     * @param message - message the header is a part of
     * @return DNSRecord object with all info parsed
     */
    public static DNSRecord decodeRecord(InputStream input, DNSMessage message) throws IOException {
        DNSRecord record = new DNSRecord();

        // get name
        record.name_ = DNSMessage.octetsToString(message.readDomainName(input));
        // get type
        byte[] type = input.readNBytes(2);
        record.type_ = ((type[0] & 0xff) << 8) | (type[1] & 0xff);
        // get class
        byte[] rclass = input.readNBytes(2);
        record.rclass_ = ((rclass[0] & 0xff) << 8) | (rclass[1] & 0xff);
        // get ttl
        byte[] ttl = input.readNBytes(4);
        record.ttl_ = ((ttl[0] & 0xff) << 24) | ((ttl[1] & 0xff) << 16) | ((ttl[2] & 0xff) << 8) | (ttl[3] & 0xff);
        // get length
        byte[] rdlength = input.readNBytes(2);
        record.rdlength_ = ((rdlength[0] & 0xff) << 8) | (rdlength[1] & 0xff);
        // get data
        // type and class of 1 suggests the data will be a 4 byte ip address
        if (record.type_ == 1 && record.rclass_ == 1) {
            byte[] ip = input.readNBytes(4);
            record.rdata_ = (ip[0] & 0xff) + "." + (ip[1] & 0xff) + "." + (ip[2] & 0xff) + "." + (ip[3] & 0xff);
        }
        else {
            byte[] rdata = input.readNBytes(record.rdlength_);
            record.rdata_ = new String(rdata, StandardCharsets.US_ASCII);
        }
        // record a timestamp to remember roughly what time this record was created to know when it will expire
        record.date_ = new Date();

        return record;
    }

    /**
     * build a standard additional record for including in most responses
     *
     * the values used in this were set to match the additional record given by Google
     *
     * @return DNSRecord representing the additional record expected in most responses
     */
    public static DNSRecord buildStandardAdditionalRecord() {
        DNSRecord record = new DNSRecord();

        record.name_ = "ROOT";
        record.type_ = 41;
        record.rclass_ = 512;
        record.ttl_ = 0;
        record.rdlength_ = 0;
        record.rdata_ = "";
        record.date_ = new Date();

        return record;
    }


    /**
     * convert the entire DNSRecord to bytes and write to the output stream
     *
     * @param output - stream to write bytes to
     * @param domainLocations - HashMap keeping track of byte locations of domain names that have been written in full so far
     */
    public void writeBytes(ByteArrayOutputStream output, HashMap<String,Integer> domainLocations) throws IOException {
        // write name
        DNSMessage.writeDomainName(output, domainLocations, DNSMessage.stringToOctets(name_));
        // write 2 bytes for type
        int outByte = (type_ >> 8) & 0xff;
        output.write(outByte);
        outByte = type_ & 0xff;
        // write 2 bytes for rclass
        output.write(outByte);
        outByte = (rclass_ >> 8) & 0xff;
        output.write(outByte);
        outByte = rclass_ & 0xff;
        output.write(outByte);
        // write 4 bytes for ttl
        outByte = (ttl_ >> 24) & 0xff;
        output.write(outByte);
        outByte = (ttl_ >> 16) & 0xff;
        output.write(outByte);
        outByte = (ttl_ >> 8) & 0xff;
        output.write(outByte);
        outByte = ttl_ & 0xff;
        output.write(outByte);
        // write 2 bytes for rdlength
        outByte = (rdlength_ >> 8) & 0xff;
        output.write(outByte);
        outByte = rdlength_ & 0xff;
        output.write(outByte);
        // write rdlength number of bytes from rdata
        if (type_ == 1 && rclass_ == 1) {
            String[] ip = rdata_.split("\\.");
            for (int i = 0; i < rdlength_; ++i) {
                output.write(Integer.parseInt(ip[i]));
            }
        }
        else {
            output.write(rdata_.getBytes(), 0, rdlength_);
        }
    }

    /**
     * determine whether the record is still valid by checking that its time to live has not elapsed
     *
     * @return true if the time to live has not elapsed, otherwise false
     */
    public boolean timestampValid() {
        Calendar expire = Calendar.getInstance();
        expire.setTime(date_);
        expire.add(Calendar.SECOND, ttl_);
        return Calendar.getInstance().before(expire);
    }

    // auto-generated functions
    @Override
    public String toString() {
        return "DNSRecord{" +
                "name_='" + name_ + '\'' +
                ", type_=" + type_ +
                ", rclass_=" + rclass_ +
                ", ttl_=" + ttl_ +
                ", rdlength_=" + rdlength_ +
                ", rdata_='" + rdata_ + '\'' +
                '}';
    }
}

