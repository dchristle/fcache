submodule (parent_module) child_module
contains
  module procedure child_procedure
    value = 42
  end procedure child_procedure
end submodule child_module
