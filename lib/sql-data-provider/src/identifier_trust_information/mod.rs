use crate::transaction_context::TransactionManagerImpl;

pub(crate) mod mapper;
mod repository;
#[cfg(test)]
mod test;

pub(crate) struct IdentifierTrustInformationProvider {
    pub db: TransactionManagerImpl,
}
