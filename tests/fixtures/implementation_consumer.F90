module implementation_consumer
  use implementation_module, only: computed_value
  implicit none
contains
  integer function consume_value(input)
    integer, intent(in) :: input
    consume_value = computed_value(input)
  end function consume_value
end module implementation_consumer
