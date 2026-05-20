<?php

declare(strict_types=1);

namespace App\Admin;

use App\Entity\User;
use Sonata\AdminBundle\Admin\AbstractAdmin;
use Sonata\AdminBundle\Form\FormMapper;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\TextType;

/**
 * Sonata admin for User — NO voter coverage (admin_authz_coverage=partial).
 * Mass-assignment / privilege-escalation surface: any ROLE_ADMIN can edit any
 * User without per-row authorization.
 */
class UserAdmin extends AbstractAdmin
{
    public function getClass(): string
    {
        return User::class;
    }

    protected function configureFormFields(FormMapper $form): void
    {
        $form
            ->add('email', EmailType::class)
            ->add('password', TextType::class)
            ->add('roles', TextType::class);
    }
}
