#[derive(Debug)]
pub enum Error {
    ExportKeyError(String),
    LoadKeyPairError(String),
    GenerateKeyPairError(String),
    DecodeBase64Error(String),
    ReadFileError(String),
}
