use utoipa::OpenApi;
fn main() {
    println!(
        "{}",
        honeyforge_backend::api::ApiDoc::openapi()
            .to_pretty_json()
            .expect("OpenAPI serializes")
    );
}
