pub(crate) mod dl14;
pub(crate) mod dl15;
pub(crate) mod dl16;
pub(crate) mod dl17;
pub(crate) mod dl18;
pub(crate) mod dl19;
pub(crate) mod dl20;
pub(crate) mod dl21;
pub(crate) mod dl22;
pub(crate) mod dl23;
pub(crate) mod dl24;
pub(crate) mod dl25;
pub(crate) mod dl26;
pub(crate) mod dl28;
pub(crate) mod dl29;
pub(crate) mod dl30;
pub(crate) mod dl31;
pub(crate) mod dl32;
pub(crate) mod dl33;
pub(crate) mod dl34;

#[cfg(test)]
pub(crate) use dl34 as latest;

mod types;

#[cfg(test)]
pub use self::types::BuiltinAccount;

#[cfg(test)]
pub(crate) use latest::accounts::BUILTIN_ACCOUNT_ANONYMOUS_DL6 as BUILTIN_ACCOUNT_ANONYMOUS;

/// Builtin System Admin account.
#[cfg(test)]
pub static BUILTIN_ACCOUNT_TEST_PERSON: BuiltinAccount = BuiltinAccount {
    account_type: netidm_proto::v1::AccountType::Person,
    entry_managed_by: None,
    name: "test_person",
    uuid: crate::constants::uuids::UUID_TESTPERSON_1,
    description: "Test Person",
    displayname: "Test Person",
};
