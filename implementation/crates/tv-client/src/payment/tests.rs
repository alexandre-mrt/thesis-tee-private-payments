use super::*;

#[test]
fn the_payee_balance_never_wraps() {
    assert_eq!(payee_balance(10, 5).unwrap(), 15);
    assert_eq!(payee_balance(u64::MAX - 1, 1).unwrap(), u64::MAX);
    assert!(matches!(
        payee_balance(u64::MAX, 1),
        Err(ClientError::ExceedsCap {
            balance: u64::MAX,
            amount: 1
        })
    ));
    assert!(matches!(
        payee_balance(u64::MAX - 1, 2),
        Err(ClientError::ExceedsCap { .. })
    ));
}
