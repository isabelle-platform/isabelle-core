use isabelle_dm::data_model::item::Item;

pub fn get_user(srv: &crate::state::data::Data, login: String) -> Option<Item> {
    for item in srv.itm["user"].get_all() {
        if item.1.strs.contains_key("login")
            && item.1.strs["login"] == login
        {
            return Some(item.1.clone());
        }
    }

    return None;
}

pub fn check_role(srv: &crate::state::data::Data, user: &Option<Item>, role: &str) -> bool {
    let role_is = srv.internals.safe_str("user_role_prefix", "role_is_");
    if user.is_none() {
        return false;
    }
    return user.as_ref()
        .unwrap()
        .safe_bool(&(role_is.to_owned() + role), false);
}
