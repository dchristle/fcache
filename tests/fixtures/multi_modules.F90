module first_module
  implicit none
  integer, parameter :: first_value = 1
end module first_module

module second_module
  use first_module, only: first_value
  implicit none
  integer, parameter :: second_value = first_value + 1
end module second_module
