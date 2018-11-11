#[macro_use] extern crate quote;

extern crate proc_macro;
extern crate syn;

use self::proc_macro::TokenStream;

#[proc_macro_derive(Hashable)]
pub fn hashable(input: TokenStream) -> TokenStream {
    // Construct a string representation of the type definition
    let s = input.to_string();
    
    // Parse the string representation
    let ast = syn::parse_derive_input(&s).unwrap();

    // Build the impl
    let gen = impl_hashable(&ast);
    
    // Return the generated impl
    gen.parse().unwrap()
}

fn impl_hashable(ast: &syn::DeriveInput) -> quote::Tokens {
    let name = &ast.ident;
    quote! {
        impl Hashable for #name {
            fn hash_self(&mut self) -> () {
                if *(&self.hash.is_none()) {
                    //
                } 
            }
        }
    }
}

#[proc_macro_derive(Signable)]
pub fn signable(input: TokenStream) -> TokenStream {
    // Construct a string representation of the type definition
    let s = input.to_string();
    
    // Parse the string representation
    let ast = syn::parse_derive_input(&s).unwrap();

    // Build the impl
    let gen = impl_signable(&ast);
    
    // Return the generated impl
    gen.parse().unwrap()
}

fn impl_signable(ast: &syn::DeriveInput) -> quote::Tokens {
    let name = &ast.ident;
    quote! {
        impl Signable for #name {
            fn sign(&mut self) -> () {
                //
            }
        }
    }
}