use ockam_core::Result;

pub trait TestSuite {
    fn run_tests<T>(test_item: T) -> Result<()>;
}
