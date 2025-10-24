use std::collections::BTreeMap;
use std::io::Read;

/// A buffer that reassembles incoming data chunks in order based on sequence numbers.
/// Similar to how TCP reassembles out-of-order packets.
#[derive(Debug)]
pub struct AppBuffer {
    received: BTreeMap<u32, Vec<u8>>, // out-of-order chunks waiting to be assembled
    expected_seq: u32,                // next byte sequence expected
    assembled: Vec<u8>,               // contiguous assembled data
    assembled_offset: usize,          // logical read position inside assembled
}

impl AppBuffer {
    /// Create a new buffer starting at the given initial sequence number.
    pub fn new(initial_seq: u32) -> Self {
        Self {
            received: BTreeMap::new(),
            expected_seq: initial_seq,
            assembled: Vec::new(),
            assembled_offset: 0,
        }
    }

    /// Insert a chunk by copying its data into internal buffer
    pub fn insert(&mut self, seq: u32, data: &[u8]) {
        if !data.is_empty() && !self.received.contains_key(&seq) {
            self.received.insert(seq, data.to_vec());
            self.try_assemble();
        }
    }

    /// Try to assemble consecutive chunks starting from the expected sequence number.
    fn try_assemble(&mut self) {
        while let Some(chunk) = self.received.remove(&self.expected_seq) {
            self.expected_seq += chunk.len() as u32;
            self.assembled.extend_from_slice(&chunk);
        }
    }

    /// Cleanup mechanism: avoid unbounded growth of assembled data
    /// by draining already-consumed bytes when offset gets too large.
    fn cleanup(&mut self) {
        if self.assembled_offset > 4096 {
            self.assembled.drain(0..self.assembled_offset);
            self.assembled_offset = 0;
        }
    }
}

impl Read for AppBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available_data = &self.assembled[self.assembled_offset..];
        let bytes_to_copy = std::cmp::min(buf.len(), available_data.len());

        if bytes_to_copy > 0 {
            buf[..bytes_to_copy].copy_from_slice(&available_data[..bytes_to_copy]);
            self.assembled_offset += bytes_to_copy;
            self.cleanup();
        }

        Ok(bytes_to_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Test inserting sequential data
    #[test]
    fn test_sequential_insert() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(1, b"h");
        buffer.insert(2, b"e");
        buffer.insert(3, b"l");
        buffer.insert(4, b"l");
        buffer.insert(5, b"o");

        let mut output = Vec::new();
        let bytes_read = buffer.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(output, b"hello");
    }

    /// Test inserting data out of order
    #[test]
    fn test_non_sequential_insert() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(5, b"o");
        buffer.insert(3, b"l");
        buffer.insert(1, b"h");
        buffer.insert(2, b"e");
        buffer.insert(4, b"l");

        let mut output = Vec::new();
        let bytes_read = buffer.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(output, b"hello");
    }

    /// Test inserting chunks with different sizes
    #[test]
    fn test_multiple_inserts() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(1, b"h");
        buffer.insert(2, b"el");
        buffer.insert(4, b"lo");

        let mut output = Vec::new();
        let bytes_read = buffer.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(output, b"hello");
    }

    /// Test when there is a missing sequence number (gap)
    #[test]
    fn test_insert_with_gap() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(1, b"h");
        buffer.insert(2, b"e");
        buffer.insert(3, b"l");
        // Missing #4
        buffer.insert(5, b"o");

        let mut output = Vec::new();
        let bytes_read = buffer.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(output, b"hel");
    }

    /// Test reading more than available data
    #[test]
    fn test_read_more_than_available() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(1, b"h");
        buffer.insert(2, b"e");
        buffer.insert(3, b"l");

        let mut partial_buf = [0u8; 4];
        let bytes_read = buffer.read(&mut partial_buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&partial_buf[0..bytes_read], b"hel");
    }

    /// Test that already-read data is not returned again
    #[test]
    fn test_data_removal_after_read() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(1, b"hello");

        let mut partial_buf = [0u8; 2];
        let bytes_read = buffer.read(&mut partial_buf).unwrap();
        assert_eq!(bytes_read, 2);
        assert_eq!(&partial_buf, b"he");

        let mut remaining_buf = Vec::new();
        let bytes_read = buffer.read_to_end(&mut remaining_buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(remaining_buf, b"llo");
    }

    /// Test cleanup mechanism (offset-based, no constant drain)
    #[test]
    fn test_cleanup_mechanism() {
        let mut buffer = AppBuffer::new(1);

        let large_data = vec![b'x'; 6000];
        buffer.insert(1, &large_data);

        let mut read_buf = vec![0u8; 5000];
        let bytes_read = buffer.read(&mut read_buf).unwrap();
        assert_eq!(bytes_read, 5000);

        // After cleanup, offset should be reset
        assert_eq!(buffer.assembled_offset, 0);
        // Remaining data = 1000 bytes
        assert_eq!(buffer.assembled.len(), 1000);
    }

    /// Test that duplicate insertions are ignored
    #[test]
    fn test_dupped_insert() {
        let mut buffer = AppBuffer::new(1);
        buffer.insert(1, b"hello");
        buffer.insert(6, b" world");
        buffer.insert(6, b" world"); // duplicate

        let mut output = Vec::new();
        let bytes_read = buffer.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 11);
        assert_eq!(output, b"hello world");

        output.clear();
        let bytes_read = buffer.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 0);
        assert_eq!(output, b"");
    }
}
