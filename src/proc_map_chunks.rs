use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Represents a chunk mapped by `/proc/self/maps`
#[allow(dead_code)]
#[derive(Debug)]
pub struct Chunk {
    /// Chunk's low and high virtual addresses
    mem: ChunkMemory,

    /// Permissions (going to be just a String instead of anything more complex for now)
    perms: String,

    /// File offset
    offset: usize,

    /// Device numbers (also going to temporarily be a string instead of a u32)
    dev: String,

    /// Inode number
    inode: usize,

    /// The backing file name
    filename: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkMemory {
    /// Low address
    pub low_addr: usize,

    /// High address
    pub high_addr: usize,
}

impl From<Chunk> for ChunkMemory {
    fn from(chunk: Chunk) -> Self {
        chunk.mem
    }
}

impl Chunk {
    pub fn is_writable(&self) -> bool {
        self.perms.contains('w')
    }

    pub fn low(&self) -> &usize {
        &self.mem.low_addr
    }

    pub fn high(&self) -> &usize {
        &self.mem.high_addr
    }

    pub fn filename(&self) -> Option<&PathBuf> {
        self.filename.as_ref()
    }
}

/// Represents all the mapping info inside `/proc/self/maps`
#[derive(Debug)]
pub struct ProcMapChunks {
    /// Vector of all the chunks
    chunks: Vec<Chunk>,
}

impl ProcMapChunks {
    /// Gets an instance of the [`ProcMapChunks`] struct based on the current process' `maps` file
    /// (`/proc/self/maps`)
    pub fn current() -> io::Result<Self> {
        Self::from_map_file("/proc/self/maps")
    }

    /// Gets an instance of the [`ProcMapChunks`] struct for the process identified by `pid`
    pub fn from_pid(pid: i32) -> io::Result<Self> {
        if pid <= 0 {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "pid must be positive"))
        } else {
            Self::from_map_file(format!("/proc/{pid}/maps"))
        }
    }

    /// Returns an iterator ([`ProcMapChunksIterator`]) over all entries in `/proc/self/maps`
    pub fn iter(&self) -> ProcMapChunksIterator<'_> {
        ProcMapChunksIterator {
            map_chunks: self,
            index: 0,
            stop_index: usize::MAX,
        }
    }

    /// Similar to [`ProcMapChunks::iter`], but returns an iterator that only iterates
    /// through the chunks between the `low_addr` and `high_addr`.
    pub fn chunks_between(&self, low_addr: usize, high_addr: usize) -> ProcMapChunksIterator<'_> {
        let start_index = self
            .chunks
            .iter()
            .enumerate()
            .find(|&(_, chunk)| chunk.low() >= &low_addr)
            .map(|tuple| tuple.0)
            .unwrap_or(usize::MAX);
        let stop_index = self
            .chunks
            .iter()
            .enumerate()
            .find(|&(_, chunk)| chunk.high() >= &high_addr)
            .map(|tuple| tuple.0)
            .unwrap_or(usize::MAX);

        ProcMapChunksIterator {
            map_chunks: self,
            index: start_index,
            stop_index,
        }
    }

    pub fn to_mem_set(&self) -> BTreeSet<ChunkMemory> {
        self.iter()
            .map(|chunk| ChunkMemory {
                low_addr: *chunk.low(),
                high_addr: *chunk.high(),
            })
            .collect()
    }

    /// Returns (as address ranges via [`Vec<ChunkMemory>`]) all writable chunks in `self` (including parts of chunks) that are not contained inside the intervals in `original_mapping_mem`
    pub fn find_new_chunks(
        &self,
        original_mapping_mem: &BTreeSet<ChunkMemory>,
    ) -> Vec<ChunkMemory> {
        let mut chunks = Vec::new(); // Result vector to become inner field of returned `ProcMapChunks`

        let original_chunks_sorted = original_mapping_mem.iter().collect::<Vec<_>>();
        let current_chunks_sorted = self
            .iter()
            .filter_map(|chunk| chunk.is_writable().then_some(&chunk.mem))
            .collect::<BTreeSet<_>>();

        let mut i = 0;

        for &current_interval in &current_chunks_sorted {
            let mut curr_start = current_interval.low_addr;

            // Skip all intervals in the original mappings that end before `current_interval` starts
            while i < original_chunks_sorted.len()
                && original_chunks_sorted[i].high_addr <= current_interval.low_addr
            {
                i += 1;
            }

            let mut j = i;
            while j < original_chunks_sorted.len()
                && original_chunks_sorted[j].low_addr < current_interval.high_addr
            {
                let original_interval = original_chunks_sorted[j];

                if original_interval.low_addr > curr_start {
                    chunks.push(ChunkMemory {
                        low_addr: curr_start,
                        high_addr: original_interval.low_addr.min(current_interval.high_addr),
                    });
                }

                curr_start = curr_start.max(original_interval.high_addr);
                if curr_start >= current_interval.high_addr {
                    break;
                }

                j += 1;
            }

            if curr_start < current_interval.high_addr {
                chunks.push(ChunkMemory {
                    low_addr: curr_start,
                    high_addr: current_interval.high_addr,
                });
            }
        }

        chunks
    }

    fn from_map_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut chunks = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            // Parse address range
            let addr_range: Vec<&str> = parts[0].split('-').collect();
            let low_addr = usize::from_str_radix(addr_range[0], 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let high_addr = usize::from_str_radix(addr_range[1], 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Parse permissions
            let perms = parts[1].to_string();

            // Parse offset
            let offset = usize::from_str_radix(parts[2], 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Parse device
            let dev = parts[3].to_string();

            // Parse inode
            let inode = parts[4]
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Parse filename (if it exists)
            let filename = if parts.len() > 5 {
                Some(PathBuf::from(parts[5..].join(" ")))
            } else {
                None
            };

            let mem = ChunkMemory {
                low_addr,
                high_addr,
            };

            chunks.push(Chunk {
                mem,
                perms,
                offset,
                dev,
                inode,
                filename,
            });
        }

        Ok(Self { chunks })
    }
}

impl<'a> IntoIterator for &'a ProcMapChunks {
    type Item = &'a Chunk;
    type IntoIter = ProcMapChunksIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for ProcMapChunks {
    type Item = Chunk;
    type IntoIter = std::vec::IntoIter<Chunk>;

    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter()
    }
}

/// Iterator struct for the [`Chunk`]s inside a [`ProcMapChunks`].
pub struct ProcMapChunksIterator<'a> {
    /// Reference to the backing ProcMapChunks
    map_chunks: &'a ProcMapChunks,

    /// Current index into `self.map_chunks.chunks` for the [`Iterator`] implementation
    index: usize,

    /// Index into `self.map_chunks.chunks` at which to stop for the [`Iterator`] implementation.
    /// The iterator will **not** include the chunk at this index.
    stop_index: usize,
}

impl<'a> Iterator for ProcMapChunksIterator<'a> {
    type Item = &'a Chunk;
    fn next(&mut self) -> Option<Self::Item> {
        // `stop_index` check
        if self.index >= self.stop_index {
            return None;
        }

        let next = self.map_chunks.chunks.get(self.index);
        self.index += 1;
        next
    }
}
