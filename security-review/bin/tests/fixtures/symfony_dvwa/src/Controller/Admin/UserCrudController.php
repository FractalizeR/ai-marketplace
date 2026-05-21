<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\User;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\ArrayField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;

class UserCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return User::class;
    }

    public function configureFields(string $pageName): iterable
    {
        // VULN: sensitive_field_unmasked id=DVWA-11
        // `apiKey` is rendered as a plaintext TextField with no `formatValue`,
        // `onlyOnIndex`, `hideOnForm`, or `hideOnIndex` modifier. Every admin
        // viewing /admin?routeName=user&action=detail sees the live key.
        // Sink_kind=sensitive_field_unmasked, root_cause_family=disclosure.
        //
        // VULN: mass_assignment id=DVWA-12
        // `roles` is editable with `ArrayField` and the controller has no voter
        // (`recon_bags.stack.symfony.admin_authz_coverage.crud_controllers_without_voter`
        // will list `UserCrudController`). Any admin escalates any user to
        // ROLE_ADMIN by editing the entity. Sink_kind=mass_assignment.
        return [
            IdField::new('id'),
            EmailField::new('email'),
            TextField::new('password'),
            TextField::new('apiKey'),
            ArrayField::new('roles'),
        ];
    }
}
