import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Objects;

/**
 * This class represents a client request
 */
public class DNSQuestion {
    private String name_;   // domain name
    private int type_;      // unsigned 16 bit qtype code specifying the type of query
    private int class_;     // unsigned 16 bit q class code specifying class of query


    /**
     * read and parse a question from the input stream
     *
     * @param input - stream to read and parse from
     * @param message - message the question is a part of
     * @return DNSQuestion with all info parsed
     */
    public static DNSQuestion decodeQuestion(InputStream input, DNSMessage message) throws IOException {
        DNSQuestion question = new DNSQuestion();

        // get name
        question.name_ = DNSMessage.octetsToString(message.readDomainName(input));
        // get type
        byte[] type = input.readNBytes(2);
        question.type_ = ((type[0] & 0xff) << 8) | (type[1] & 0xff);
        // get class
        byte[] qclass = input.readNBytes(2);
        question.class_ = ((qclass[0] & 0xff) << 8) | (qclass[1] & 0xff);

        return question;
    }

    /**
     * convert the entire DNSQuestion to bytes and write to the output stream
     *
     * @param output - stream to write bytes to
     * @param domainLocations - HashMap keeping track of byte locations of domain names that have been written in full so far
     */
    public void writeBytes(ByteArrayOutputStream output, HashMap<String,Integer> domainLocations) throws IOException {
        // write name
        DNSMessage.writeDomainName(output, domainLocations, DNSMessage.stringToOctets(name_));
        // write type
        int outByte = (type_ >> 8) & 0xff;
        output.write(outByte);
        outByte = type_ & 0xff;
        output.write(outByte);
        // write class
        outByte = (class_ >> 8) & 0xff;
        output.write(outByte);
        outByte = class_ & 0xff;
        output.write(outByte);
    }

    // auto-generated functions
    @Override
    public String toString() {
        return "DNSQuestion{" +
                "name_='" + name_ + '\'' +
                ", type_=" + type_ +
                ", class_=" + class_ +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DNSQuestion that = (DNSQuestion) o;
        return type_ == that.type_ && class_ == that.class_ && Objects.equals(name_, that.name_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name_, type_, class_);
    }
}
