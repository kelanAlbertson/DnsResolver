import java.util.HashMap;

/**
 * This class is the local cache.
 *
 * For simplicity, this only stores the first answer for a question
 * It should basically just have a HashMap<DNSQuestion, DNSRecord> in it.
 * This class should have methods for querying and inserting records into the cache.
 * When you look up an entry, if it is too old (its TTL has expired), remove it and return "not found."
 */
public class DNSCache {
    private final HashMap<DNSQuestion, DNSRecord> cache_;

    public DNSCache() {
        cache_ = new HashMap<>();
    }

    /**
     * tells whether a question has a valid answer in the cache and removes the cache entry if it exists but is expired
     *
     * @param question - question to search for an entry in the cache
     * @return true if the cache holds a valid answer for the question, otherwise returns false
     */
    public boolean hasValidResponse (DNSQuestion question) {
        if (cache_.containsKey(question)) {
            // check to see if ttl has passed
            if (cache_.get(question).timestampValid()) {
                return true;
            }
            // if answer was in cache but is expired then remove it from cache
            else {
                cache_.remove(question);
            }
        }
        return false;
    }

    /**
     * retrieve the entry from the cache
     *
     * @param question - question to retrieve entry answer for
     * @return answer responding to the provided question or null if the key does not exist
     */
    public DNSRecord getAnswer (DNSQuestion question) {
        return cache_.get(question);
    }

    /**
     * add the question and answer pair to the cache
     *
     * @param question - question to be cached
     * @param answer - answer to question
     */
    public void add (DNSQuestion question, DNSRecord answer) {
        cache_.put(question, answer);
    }
}
