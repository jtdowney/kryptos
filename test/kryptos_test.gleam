import unitest

pub fn main() -> Nil {
  unitest.run(
    unitest.Options(
      ..unitest.default_options(),
      ignored_tags: ["wycheproof"],
      execution_mode: unitest.RunParallelAuto,
    ),
  )
}
