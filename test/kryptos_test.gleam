import unitest.{Options}

pub fn main() -> Nil {
  unitest.run(
    Options(..unitest.default_options(), ignored_tags: ["wycheproof"]),
  )
}
