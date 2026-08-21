module parent_module
  implicit none

  interface
    module subroutine child_procedure(value)
      integer, intent(out) :: value
    end subroutine child_procedure
  end interface
end module parent_module
