//! Nonmoving, page-backed records. Page ownership belongs to the supplying
//! infrastructure allocator; linked storage never frees or relocates a page.
//!
//! Record pages are uniform, so a record index names its page by division, and
//! an inline page directory turns that into a constant-time lookup. A walk
//! would instead cost one dereference per page the table has grown, on every
//! hot allocation path — the cost this storage exists to remove. The directory
//! bounds how many pages one table may hold; it is an addressing limit that
//! refuses explicitly, not a record capacity the image reserves up front.

use core::{
    marker::PhantomData,
    mem,
    ops::{Index, IndexMut},
    ptr::NonNull,
};

const PAGE_BYTES: usize = 4096;
/// Record pages the inline directory addresses: 32 KiB of pointers, which is
/// every table's whole need on a small machine.
const MAX_PAGES: usize = 4096;
/// Pointers one directory page holds.
const DIRECTORY_ENTRIES: usize = PAGE_BYTES / mem::size_of::<Option<NonNull<Header>>>();
/// Directory pages beyond the inline directory. Each is funded on demand like
/// a record page, so a table grows with admitted memory instead of stopping at
/// the inline bound; this bound only keeps the inline table of them small.
const MAX_DIRECTORY_PAGES: usize = 64;

#[repr(C)]
struct DirectoryPage([Option<NonNull<Header>>; DIRECTORY_ENTRIES]);

#[repr(C)]
struct Header {
    next: Option<NonNull<Header>>,
}

pub(super) struct Segmented<T: Copy> {
    first: Option<NonNull<Header>>,
    last: Option<NonNull<Header>>,
    directory: [Option<NonNull<Header>>; MAX_PAGES],
    overflow: [Option<NonNull<DirectoryPage>>; MAX_DIRECTORY_PAGES],
    overflow_len: usize,
    pages: usize,
    capacity: usize,
    marker: PhantomData<T>,
    #[cfg(test)]
    host_pages: alloc::vec::Vec<alloc::boxed::Box<HostPage>>,
}

#[cfg(test)]
#[repr(C, align(4096))]
struct HostPage([u8; PAGE_BYTES]);

impl<T: Copy> Segmented<T> {
    pub const fn new() -> Self {
        Self {
            first: None,
            last: None,
            directory: [None; MAX_PAGES],
            overflow: [None; MAX_DIRECTORY_PAGES],
            overflow_len: 0,
            pages: 0,
            capacity: 0,
            marker: PhantomData,
            #[cfg(test)]
            host_pages: alloc::vec::Vec::new(),
        }
    }

    const fn offset() -> usize {
        mem::size_of::<Header>().next_multiple_of(mem::align_of::<T>())
    }

    pub const fn entries_per_page() -> usize {
        if mem::size_of::<T>() == 0 || mem::align_of::<T>() > PAGE_BYTES {
            return 0;
        }
        (PAGE_BYTES - Self::offset()) / mem::size_of::<T>()
    }

    pub const fn len(&self) -> usize {
        self.capacity
    }

    /// Whether the next record page needs a directory page first.
    pub const fn needs_directory_page(&self) -> bool {
        self.pages >= MAX_PAGES && self.pages - MAX_PAGES == self.overflow_len * DIRECTORY_ENTRIES
    }

    /// Add one directory page, which must be exactly when one is needed.
    ///
    /// The caller transfers the page exactly as for [`Self::append`].
    pub unsafe fn add_directory_page(&mut self, page: NonNull<u8>) -> Result<(), ()> {
        if !self.needs_directory_page()
            || self.overflow_len == MAX_DIRECTORY_PAGES
            || !(page.as_ptr() as usize).is_multiple_of(PAGE_BYTES)
        {
            return Err(());
        }
        let directory = page.cast::<DirectoryPage>();
        // SAFETY: the caller provides a uniquely writable page; a directory
        // page is exactly one page of pointers.
        unsafe {
            directory
                .as_ptr()
                .write(DirectoryPage([None; DIRECTORY_ENTRIES]))
        };
        self.overflow[self.overflow_len] = Some(directory);
        self.overflow_len += 1;
        Ok(())
    }

    /// The record page with ordinal `page`, inline or through a directory page.
    fn page_header(&self, page: usize) -> Option<NonNull<Header>> {
        if page < MAX_PAGES {
            return self.directory[page];
        }
        let over = page - MAX_PAGES;
        let directory = (*self.overflow.get(over / DIRECTORY_ENTRIES)?)?;
        // SAFETY: an installed directory page stays mapped and unmoved for this
        // storage's lifetime, and only `append` writes it, through `&mut self`.
        unsafe { (*directory.as_ptr()).0[over % DIRECTORY_ENTRIES] }
    }

    /// The caller transfers exclusive access to a writable, page-aligned 4 KiB
    /// mapping for the storage's lifetime. It must not supply a page twice or
    /// unmap/reuse it while this storage or an entry reference remains alive.
    pub unsafe fn append(&mut self, page: NonNull<u8>, empty: T) -> Result<(), ()> {
        let count = Self::entries_per_page();
        if count == 0
            || self.needs_directory_page()
            || !(page.as_ptr() as usize).is_multiple_of(PAGE_BYTES)
        {
            return Err(());
        }

        let capacity = self.capacity.checked_add(count).ok_or(())?;
        // Resolved before anything is written, so a refusal changes nothing.
        let overflow = match self.pages.checked_sub(MAX_PAGES) {
            Some(over) => Some((self.overflow[over / DIRECTORY_ENTRIES].ok_or(())?, over)),
            None => None,
        };
        let header = page.cast::<Header>();
        // SAFETY: the caller provides a uniquely writable page. Header and
        // records occupy disjoint, aligned regions entirely within that page.
        unsafe {
            header.as_ptr().write(Header { next: None });
            let entries = page.as_ptr().add(Self::offset()).cast::<T>();
            for index in 0..count {
                entries.add(index).write(empty);
            }
            if let Some(mut last) = self.last {
                last.as_mut().next = Some(header);
            }
        }
        if self.first.is_none() {
            self.first = Some(header);
        }
        match overflow {
            None => self.directory[self.pages] = Some(header),
            // SAFETY: the installed directory page is exclusively this
            // storage's, and `&mut self` excludes every other access to it.
            Some((directory, over)) => unsafe {
                (*directory.as_ptr()).0[over % DIRECTORY_ENTRIES] = Some(header);
            },
        }
        self.last = Some(header);
        self.pages += 1;
        self.capacity = capacity;
        Ok(())
    }

    fn entry_ptr(&self, index: usize) -> Option<NonNull<T>> {
        if index >= self.capacity {
            return None;
        }
        let entries = Self::entries_per_page();
        let header = self.page_header(index / entries)?;
        // SAFETY: every directory entry below `pages` names an appended page
        // that stays mapped and unmoved for this storage's lifetime, and the
        // computed record is initialized and inside that page.
        Some(unsafe {
            NonNull::new_unchecked(
                header
                    .as_ptr()
                    .cast::<u8>()
                    .add(Self::offset())
                    .cast::<T>()
                    .add(index % entries),
            )
        })
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        // SAFETY: shared entry references are bounded by the storage borrow.
        self.entry_ptr(index).map(|entry| unsafe { entry.as_ref() })
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        // SAFETY: an exclusive storage borrow excludes any other entry access.
        self.entry_ptr(index)
            .map(|mut entry| unsafe { entry.as_mut() })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        let mut page = self.first;
        let mut offset = 0;
        core::iter::from_fn(move || {
            let header = page?;
            // SAFETY: exclusive storage access and a forward-only traversal
            // yield each disjoint initialized record at most once.
            unsafe {
                let entry = header
                    .as_ptr()
                    .cast::<u8>()
                    .add(Self::offset())
                    .cast::<T>()
                    .add(offset);
                offset += 1;
                if offset == Self::entries_per_page() {
                    page = header.as_ref().next;
                    offset = 0;
                }
                Some(&mut *entry)
            }
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        let mut page = self.first;
        let mut offset = 0;
        core::iter::from_fn(move || {
            let header = page?;
            // SAFETY: the iterator holds the storage's shared borrow, and every
            // published page contains exactly entries_per_page initialized records.
            unsafe {
                let entry = header
                    .as_ptr()
                    .cast::<u8>()
                    .add(Self::offset())
                    .cast::<T>()
                    .add(offset);
                offset += 1;
                if offset == Self::entries_per_page() {
                    page = header.as_ref().next;
                    offset = 0;
                }
                Some(&*entry)
            }
        })
    }
}

#[cfg(test)]
impl<T: Copy> Segmented<T> {
    pub fn provision_host(&mut self, entries: usize, empty: T) {
        while self.capacity < entries {
            let mut page = alloc::boxed::Box::new(HostPage([0; PAGE_BYTES]));
            let pointer = NonNull::from(&mut page.0).cast();
            // SAFETY: Box keeps each page stable and exclusively owned until
            // this storage is dropped. Its page list never exposes the bytes.
            unsafe { self.append(pointer, empty).expect("host record page") };
            self.host_pages.push(page);
        }
    }
}

impl<T: Copy> Index<usize> for Segmented<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        self.get(index).expect("record index")
    }
}

impl<T: Copy> IndexMut<usize> for Segmented<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.get_mut(index).expect("record index")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;

    #[repr(C, align(4096))]
    struct Page([u8; PAGE_BYTES]);

    #[test]
    fn pages_preserve_indices_addresses_and_initialization() {
        let mut first = Box::new(Page([0; PAGE_BYTES]));
        let mut second = Box::new(Page([0; PAGE_BYTES]));
        let mut records = Segmented::<u64>::new();
        let per_page = Segmented::<u64>::entries_per_page();
        // SAFETY: pages are unique, aligned, and outlive records and its borrows.
        unsafe {
            records
                .append(NonNull::from(&mut first.0).cast(), 7)
                .unwrap();
        }
        assert_eq!(records.len(), per_page);
        *records.get_mut(per_page - 1).unwrap() = 99;
        let address = records.get(per_page - 1).unwrap() as *const u64;
        // SAFETY: the second page is unique, aligned, and outlives records.
        unsafe {
            records
                .append(NonNull::from(&mut second.0).cast(), 11)
                .unwrap();
        }
        assert_eq!(records.len(), 2 * per_page);
        assert_eq!(records.get(per_page - 1).unwrap() as *const u64, address);
        assert_eq!(records.get(per_page - 1), Some(&99));
        assert_eq!(records.get(per_page), Some(&11));
        assert_eq!(records.iter().count(), 2 * per_page);
        assert_eq!(records.get(2 * per_page), None);
        assert_eq!(records.get(usize::MAX), None);
    }

    #[test]
    fn a_table_grows_past_its_inline_directory_through_directory_pages() {
        let mut records = Segmented::<u64>::new();
        let per_page = Segmented::<u64>::entries_per_page();
        let mut pages = std::vec::Vec::new();
        let mut page = || {
            let mut page = Box::new(Page([0; PAGE_BYTES]));
            let pointer = NonNull::from(&mut page.0).cast();
            pages.push(page);
            pointer
        };
        for _ in 0..MAX_PAGES {
            // SAFETY: every page is unique, aligned, and outlives `records`.
            unsafe { records.append(page(), 1).unwrap() };
        }
        assert!(records.needs_directory_page());
        // SAFETY: as above.
        assert_eq!(unsafe { records.append(page(), 1) }, Err(()));
        // SAFETY: as above.
        unsafe { records.add_directory_page(page()).unwrap() };
        assert!(!records.needs_directory_page());
        // SAFETY: as above; a second directory page is refused until needed.
        assert_eq!(unsafe { records.add_directory_page(page()) }, Err(()));
        // SAFETY: as above.
        unsafe { records.append(page(), 2).unwrap() };
        let index = MAX_PAGES * per_page;
        assert_eq!(records.len(), index + per_page);
        assert_eq!(records.get(index - 1), Some(&1));
        assert_eq!(records.get(index), Some(&2));
        *records.get_mut(index + per_page - 1).unwrap() = 3;
        assert_eq!(records.get(index + per_page - 1), Some(&3));
        assert_eq!(records.iter().count(), index + per_page);
        assert_eq!(records.get(index + per_page), None);
    }
}
